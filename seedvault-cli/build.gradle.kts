/*
 * SPDX-FileCopyrightText: 2024 The Calyx Institute
 * SPDX-License-Identifier: Apache-2.0
 */

import org.gradle.api.tasks.testing.logging.TestExceptionFormat

plugins {
    kotlin("jvm") version "2.1.10"
    id("com.google.protobuf") version "0.9.5"
    id("io.github.goooler.shadow") version "8.1.3"
    application
}

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

kotlin {
    jvmToolchain(17)
}

application {
    mainClass.set("org.calyxos.seedvault.cli.MainKt")
}

// Share proto definitions from the parent project without compiling the Android modules.
// We regenerate the proto classes inside this standalone project using the same .proto files.
sourceSets {
    main {
        proto {
            srcDir("${projectDir.parent}/app/src/main/proto")
            srcDir("${projectDir.parent}/storage/lib/src/main/proto")
        }
    }
}

protobuf {
    protoc {
        artifact = if ("aarch64" == System.getProperty("os.arch")) {
            "com.google.protobuf:protoc:3.21.12:osx-x86_64"
        } else {
            "com.google.protobuf:protoc:3.21.12"
        }
    }
    generateProtoTasks {
        all().forEach { task ->
            task.builtins {
                named("java") {
                    option("lite")
                }
            }
        }
    }
}

dependencies {
    implementation(kotlin("stdlib"))
    implementation(kotlin("stdlib-jdk8"))
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core-jvm:1.10.1")

    // Crypto: non-Android Tink variant (pure JVM, same AesGcmHkdfStreaming API)
    implementation("com.google.crypto.tink:tink:1.17.0")

    // Protobuf lite runtime
    implementation("com.google.protobuf:protobuf-javalite:3.21.12")
    implementation("com.google.protobuf:protobuf-kotlin-lite:3.21.12")

    // Zstd decompression (fat JAR with native libs for all platforms from Maven Central)
    implementation("com.github.luben:zstd-jni:1.5.7-3")

    // BIP39 mnemonic support (same JAR the app uses)
    implementation(
        fileTree("${projectDir.parent}/libs") {
            include("kotlin-bip39-jvm-*.jar")
        }
    )

    // CLI argument parsing
    implementation("com.github.ajalt.clikt:clikt:4.4.0")

    // Logging
    implementation("io.github.oshai:kotlin-logging-jvm:7.0.7")
    implementation("org.slf4j:slf4j-api:2.0.16")

    // Runtime: send SLF4J output to stderr
    runtimeOnly("org.slf4j:slf4j-simple:2.0.16")

    testImplementation(kotlin("test"))
    testImplementation("org.junit.jupiter:junit-jupiter-api:5.10.2")
    testImplementation("org.junit.jupiter:junit-jupiter-params:5.10.2")
    testImplementation("io.mockk:mockk:1.14.2")
    testImplementation("org.slf4j:slf4j-simple:2.0.16")
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:5.10.2")
}

tasks.withType<Test>().configureEach {
    useJUnitPlatform()
    testLogging {
        events("passed", "skipped", "failed")
        showExceptions = true
        showCauses = true
        showStackTraces = true
        exceptionFormat = TestExceptionFormat.FULL
    }
}

tasks.shadowJar {
    archiveBaseName.set("seedvault-cli")
    archiveClassifier.set("")
    mergeServiceFiles()
}

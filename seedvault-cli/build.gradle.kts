/*
 * SPDX-FileCopyrightText: 2024 The Calyx Institute
 * SPDX-License-Identifier: Apache-2.0
 */

import com.google.protobuf.gradle.id
import org.gradle.api.tasks.testing.logging.TestExceptionFormat

plugins {
    alias(libs.plugins.jetbrains.kotlin.jvm)
    alias(libs.plugins.google.protobuf)
    alias(libs.plugins.shadow)
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

sourceSets {
    main {
        proto {
            // Reuse proto definitions from app and storage:lib without depending on those modules
            srcDir("${rootProject.projectDir}/app/src/main/proto")
            srcDir("${rootProject.projectDir}/storage/lib/src/main/proto")
        }
    }
}

protobuf {
    protoc {
        artifact = if ("aarch64" == System.getProperty("os.arch")) {
            // mac m1
            "com.google.protobuf:protoc:${libs.versions.protobuf.get()}:osx-x86_64"
        } else {
            "com.google.protobuf:protoc:${libs.versions.protobuf.get()}"
        }
    }
    generateProtoTasks {
        all().forEach { task ->
            task.plugins {
                id("java") {
                    option("lite")
                }
                id("kotlin") {
                    option("lite")
                }
            }
        }
    }
}

dependencies {
    implementation(libs.kotlin.stdlib)
    implementation(libs.kotlin.stdlib.jdk8)
    implementation(libs.kotlinx.coroutines.core.jvm)

    // Crypto: use the non-Android tink variant (pure JVM, same AesGcmHkdfStreaming API)
    implementation(libs.google.tink)

    // Protobuf lite runtime
    implementation(libs.google.protobuf.javalite)
    implementation(
        fileTree("${rootProject.rootDir}/libs").include("protobuf-kotlin-lite-*.jar")
    )

    // Zstd decompression (fat JAR with native libs for all platforms from Maven Central)
    implementation(libs.zstd.jni)

    // BIP39 mnemonic support (same JAR the app uses)
    implementation(fileTree("${rootProject.rootDir}/libs").include("kotlin-bip39-jvm-*.jar"))

    // CLI argument parsing
    implementation(libs.clikt)

    // Logging
    implementation(libs.kotlin.logging)
    implementation(libs.slf4j.api)

    testImplementation(kotlin("test"))
    testImplementation(libs.junit.jupiter.api)
    testImplementation(libs.junit.jupiter.params)
    testImplementation(libs.mockk)
    testImplementation(libs.slf4j.simple)
    testRuntimeOnly(libs.junit.jupiter.engine)
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

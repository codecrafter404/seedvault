# Seedvault CLI

A cross-platform command-line tool for decrypting [Seedvault](https://github.com/seedvault-app/seedvault) backup repositories without Android.

## Overview

Seedvault stores encrypted backups in a directory called `.SeedVaultAndroidBackup/` (or `.SeedVaultBackup/`). This CLI tool lets you decrypt and restore those backups on any machine with Java 17+ using only the 12-word BIP39 recovery phrase.

### Supported backup formats

| Format | Description |
|--------|-------------|
| App backups v2 | `.snapshot` files inside 64-char hex repo folders |
| File/media backups | `.SeedSnap` files inside `<androidId>.sv` folders |

Legacy v0/v1 app backups (`<token>/.backup.metadata`) are **not** supported by this tool.

## Building

### Prerequisites

- Java 17+

### Build the fat JAR

From the repository root:

```bash
cd seedvault-cli
./gradlew shadowJar
```

This produces `build/libs/seedvault-cli.jar` — a self-contained fat JAR (~25 MB) that includes all runtime dependencies.

Alternatively, you can use the parent project's Gradle wrapper:

```bash
# From the repo root
./gradlew -p seedvault-cli shadowJar
```

## Usage

```
java -jar seedvault-cli.jar [OPTIONS] COMMAND [ARGS]
```

### List snapshots

Discover all available app and file backup snapshots:

```bash
java -jar seedvault-cli.jar list /path/to/.SeedVaultAndroidBackup
# Prompts for 12-word recovery phrase (input is hidden)
```

Or supply the mnemonic directly (e.g. for scripting):

```bash
SEEDVAULT_MNEMONIC="word1 word2 ... word12" \
  java -jar seedvault-cli.jar list /path/to/.SeedVaultAndroidBackup
```

### Decrypt app backups

Restore all apps from a snapshot to a directory.  Each app is written as a tar stream to `<output-dir>/<packageName>.tar`:

```bash
java -jar seedvault-cli.jar decrypt-app \
  --snapshot <64-char-hex-hash> \
  --output-dir /path/to/output \
  /path/to/.SeedVaultAndroidBackup
```

Restore only a specific package:

```bash
java -jar seedvault-cli.jar decrypt-app \
  --snapshot <hash> \
  --output-dir /tmp/restore \
  --package com.example.myapp \
  /path/to/.SeedVaultAndroidBackup
```

### Decrypt file/media backups

Restore files from a file backup snapshot, preserving the original relative path structure:

```bash
java -jar seedvault-cli.jar decrypt-files \
  --snapshot <13-digit-timestamp> \
  --output-dir /path/to/output \
  /path/to/.SeedVaultAndroidBackup
```

## How it works

### Key derivation

```
12-word mnemonic
    │
    ▼  BIP39 PBKDF2-SHA512 (2048 iterations)
64-byte seed
    ├── bytes 0–31  → legacy backup key (not used by this tool)
    └── bytes 32–63 → main key (HmacSHA256)
                            │
                            ▼  HKDF-expand
                  ┌─────────────────────────┐
                  │ "app backup stream key"  │ → AesGcmHkdfStreaming key for app blobs
                  │ "app backup repoId key"  │ → HMAC key for repo folder name
                  │ "stream key"             │ → AesGcmHkdfStreaming key for file chunks
                  └─────────────────────────┘
```

### App backup file format

Each blob/snapshot file contains:
```
[1 byte: version=0x02]
[Tink AesGcmHkdfStreaming ciphertext]
  └── decrypted plaintext:
       [4 bytes: compressed size (big-endian)]
       [N bytes: zstd-compressed data]
       [optional padding bytes (discarded)]
```

### File backup file format

Each chunk/SeedSnap file contains:
```
[1 byte: version=0x00]
[Tink AesGcmHkdfStreaming ciphertext with AAD]
  └── decrypted plaintext: raw file data (or protobuf for .SeedSnap)
```

## Architecture

```
seedvault-cli/
├── build.gradle.kts                 ← Standalone JVM build (no Android plugin)
├── settings.gradle.kts              ← Standalone settings (no Android subprojects)
└── src/main/kotlin/org/calyxos/seedvault/cli/
    ├── Main.kt                      ← Entry point / root Clikt command
    ├── commands/
    │   ├── ListCommand.kt           ← 'list' subcommand
    │   ├── DecryptAppCommand.kt     ← 'decrypt-app' subcommand
    │   ├── DecryptFilesCommand.kt   ← 'decrypt-files' subcommand
    │   └── MnemonicPrompt.kt        ← Secure mnemonic input
    ├── crypto/
    │   ├── Hkdf.kt                  ← HKDF-expand (RFC 5869, HmacSHA256, pure JVM)
    │   ├── JvmKeyManager.kt         ← In-memory key holder (seed bytes 32–63)
    │   └── MnemonicKeyDeriver.kt    ← BIP39 → 64-byte seed → JvmKeyManager
    └── restore/
        ├── BackupDecryptor.kt       ← AesGcmHkdfStreaming decrypt + zstd decompress
        ├── PaddedInputStream.kt     ← Strips padding from app backup streams
        ├── AppBackupRestorer.kt     ← Scans repo dirs, reads snapshots, extracts tars
        └── FileBackupRestorer.kt    ← Scans .sv dirs, decrypts chunks, writes files
```

## Security notes

- The mnemonic is **never written to disk or logged**. It is read interactively with echo disabled (when a terminal is available) or via the `SEEDVAULT_MNEMONIC` environment variable.
- Keys are derived fresh from the mnemonic on each run and held only in memory.
- File integrity is verified via SHA-256 before decryption (for app backup blobs).
- Authenticated encryption (AES-GCM) ensures ciphertext tampering is detected.

## Running tests

```bash
cd seedvault-cli
./gradlew test
```

Tests are pure JVM — no Android emulator or Robolectric needed.

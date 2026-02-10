# 🛠 Toolbox – Advanced CLI Utilities

**Developed by:** Syed Shaheer Hussain
**Year:** 2026
**Copyright:** © 2026 Syed Shaheer Hussain

**One-line description:**

> Toolbox is a comprehensive Rust-based CLI utility suite offering a collection of developer, security, cryptography, and productivity tools in a single command-line interface.

## 📌 Introduction

Toolbox is a **multi-functional command-line utility** built in Rust. It combines tools for **cryptography, encoding/decoding, text manipulation, scheduling, random generation, compression, JSON/JSON Web Token handling, terminal UI, and more**.

**Purpose:**

* To have a single, portable CLI tool for developers and security enthusiasts.
* To provide utilities that are normally scattered across multiple scripts or software.
* To help users handle encryption, encoding, formatting, and system tasks safely.

Perfect! Since your project now **builds cleanly**, let’s summarize how you can **run, install, and execute each tool command**. I’ll go step by step so everything works as expected.

---

## **1️⃣ Run commands using Cargo**

Use:

```bash
cargo run -- <command> [arguments]

```

**Examples:**

| Command        | Example                                                                     | What it does                             |
| -------------- | --------------------------------------------------------------------------- | ---------------------------------------- |
| `uuid`         | `cargo run -- uuid`                                                         | Generates a new UUID                     |
| `timestamp`    | `cargo run -- timestamp`                                                    | Prints current UNIX timestamp            |
| `jsonpretty`   | `cargo run -- jsonpretty '{"foo": "bar"}'`                                  | Pretty-prints JSON                       |
| `jsonminify`   | `cargo run -- jsonminify '{"foo": "bar"}'`                                  | Minifies JSON                            |
| `base64encode` | `cargo run -- base64encode "hello world"`                                   | Encodes string in Base64                 |
| `base64decode` | `cargo run -- base64decode "aGVsbG8gd29ybGQ="`                              | Decodes Base64                           |
| `aesencrypt`   | `cargo run -- aesencrypt "mysecretkey1234567890123456" "Hello"`             | AES-256 encrypts text                    |
| `aesdecrypt`   | `cargo run -- aesdecrypt "mysecretkey1234567890123456" "<iv>:<ciphertext>"` | AES-256 decrypts text                    |
| `password`     | `cargo run -- password 12`                                                  | Generates a random 12-character password |

> Note: For AES encryption/decryption, the key **must be exactly 32 bytes** (Aes256).

## **2️⃣ Build a standalone executable**

To **build a release version**:

```bash
cargo build --release

```

This creates the binary at:

```
target/release/toolbox.exe   # on Windows
target/release/toolbox       # on Linux/macOS

```

You can then run it **without Cargo**:

```bash
.\target\release\toolbox.exe uuid

```

or

```bash
./target/release/toolbox timestamp
```

## **3️⃣ Install globally (optional)**

If you want to use `toolbox` like any system command:

```bash
cargo install --path .

```

After that, `toolbox` will be in your PATH, so you can run anywhere:

```bash
toolbox uuid
toolbox jsonpretty '{"a": 1}'
toolbox password 16

```

## **4️⃣ Run TUI (terminal UI)**

```bash
cargo run -- tui

```

It will open the Ratatui interface.

## ✅ Notes & Tips

1. **Case-sensitivity:** Currently, commands are case-sensitive (`uuid` works, `UUID` does not).

   * If you want **fully case-insensitive commands**, I can update the code using Clap’s `ArgEnum` or manual mapping.

2. **AES Encryption/Decryption:**

   * Always use **32-character key** (Aes256)
   * Decryption input must be `<iv>:<ciphertext>` in hex format.

3. **Clipboard or stdin support:**

   * Some commands like `base64encode` read stdin if no argument is passed.

**Why it was made:**

* To save time and effort in using multiple tools for small tasks.
* To provide a secure and local environment for sensitive operations.
* To explore Rust capabilities for fast, reliable, and memory-safe CLI applications.

## 🎯 Objectives

1. Provide a unified CLI for multiple development and security tasks.
2. Offer tools for cryptography: AES encryption, hashing, HMAC, UUID generation.
3. Include encoding/decoding utilities: Base64, Base32, URL encoding.
4. Facilitate JSON handling: pretty-print, minify, JWT signing/decoding.
5. Include randomization tools: passwords, numbers, lorem text.
6. Offer compression and decompression with gzip.
7. Provide a terminal-based UI for easier interaction (`tui` command).
8. Generate command completions for PowerShell.

## 🧩 Features

* **UUID & Timestamp:** Generate unique identifiers and current UNIX timestamp.
* **JSON Tools:** Pretty-print and minify JSON strings.
* **JWT Tools:** Sign and decode JSON Web Tokens.
* **Encoding/Decoding:** Base64, Base32, URL encoding/decoding.
* **Regex Tester:** Test regular expressions against text.
* **Cryptography:** AES-256 encryption/decryption, SHA-256 hashing, HMAC-SHA256.
* **Text & Random Utilities:** Lorem generator, random numbers, password generator, ASCII codes.
* **Compression:** Gzip compress/decompress files.
* **Cron Scheduler:** Compute next run times from cron expressions.
* **Terminal UI:** Interactive Ratatui interface.
* **Command Completions:** Generate PowerShell completions.

## ⚙️ Functions / Commands

| Command | Example | Description |
| --- | --- | --- |
| `uuid` | `toolbox uuid` | Generates a new UUID |
| `timestamp` | `toolbox timestamp` | Prints UNIX timestamp |
| `jsonpretty` | `toolbox jsonpretty '{"foo": "bar"}'` | Pretty-print JSON |
| `jsonminify` | `toolbox jsonminify '{"foo": "bar"}'` | Minify JSON |
| `base64encode` | `toolbox base64encode "hello"` | Base64 encode string |
| `base64decode` | `toolbox base64decode "aGVsbG8="` | Base64 decode string |
| `base32encode` | `toolbox base32encode "text"` | Base32 encode string |
| `base32decode` | `toolbox base32decode "MFRA"` | Base32 decode string |
| `urlencode` | `toolbox urlencode "hello world"` | URL encode string |
| `urldecode` | `toolbox urldecode "hello%20world"` | URL decode string |
| `regex` | `toolbox regextest "\\d+" "123"` | Test regex |
| `jwt` | `toolbox jwtsign '{"id":1}' "secret"` | Sign JWT |
| `jwtdecode` | `toolbox jwtdecode "<token>"` | Decode JWT |
| `hash` | `toolbox hash "text"` | SHA256 hash |
| `hmac` | `toolbox hmac "key" "message"` | HMAC-SHA256 |
| `aesencrypt` | `toolbox aesencrypt "32charkey..." "text"` | AES-256 encrypt |
| `aesdecrypt` | `toolbox aesdecrypt "32charkey..." "<iv>:<ciphertext>"` | AES-256 decrypt |
| `password` | `toolbox password 12` | Random password |
| `random` | `toolbox random 1 100` | Random number |
| `lorem` | `toolbox lorem 10` | Generate lorem words |
| `upper` | `toolbox upper "text"` | Uppercase |
| `lower` | `toolbox lower "TEXT"` | Lowercase |
| `ascii` | `toolbox ascii "text"` | Print ASCII codes |
| `gzipcompress` | `toolbox gzipcompress file.txt` | Compress file |
| `gzipdecompress` | `toolbox gzipdecompress file.gz` | Decompress file |
| `cronnext` | `toolbox cronnext "* * * * *"` | Next cron run |
| `tui` | `toolbox tui` | Launch interactive terminal UI |
| `completions` | `toolbox completions` | Generate PowerShell completion |

## 🏗 Technologies Used

* **Rust** – System programming language for performance and safety.
* **Clap** – CLI argument parser.
* **Clap Complete** – Generate shell completions.
* **Ratatui** – Terminal UI toolkit.
* **AES, HMAC, SHA2** – Cryptography.
* **Base64/Base32** – Encoding.
* **Flate2** – Gzip compression.
* **Regex** – Text pattern matching.
* **UUID** – Universally unique IDs.
* **Chrono & Cron** – Date/time utilities.
* **Rand & OsRng** – Randomization.

## 🗂 Project Structure

```
toolbox/
├─ src/
│  ├─ main.rs          # Main code with all commands
├─ Cargo.toml          # Rust project config
├─ Cargo.lock          # Dependency lock
└─ target/             # Compilation output

```

## 🔧 Installation & Running

### **1️⃣ Run directly via Cargo**

```bash
cargo run -- <command> [arguments]

```

### **2️⃣ Build Release Executable**

```bash
cargo build --release

```

### Run without Cargo:

## Windows

```
.\target\release\toolbox.exe uuid

```
## Linux/Mac

```
./target/release/toolbox uuid

```

### **3️⃣ Install Globally**

```bash
cargo install --path .

```

Now you can run anywhere:

```bash

toolbox uuid

```
```
toolbox password 16

```

### **4️⃣ Terminal UI**

```bash
cargo run -- tui

```

## ⚙️ How it Works

* Each **command** is implemented as a `Subcommand` of Clap’s `Parser`.
* Arguments are validated and optionally read from stdin.
* Cryptography functions use AES, SHA256, and HMAC implementations.
* Encoding/decoding uses standard Base64/Base32 and URL encoding crates.
* `tui` command uses Ratatui to render a block-based terminal interface.
* Gzip compress/decompress uses Flate2 streams.

## 🛡 Safety & Security

* All operations are **local**, no data is sent to external servers.
* **AES key must be 32 bytes**, never share keys publicly.
* **Passwords & tokens** should be handled securely.
* Be cautious with file paths to avoid overwriting files.
* Use `cargo install` to avoid running unknown binaries from internet.
* Verify commands before running sensitive operations.

## ⚠️ Disclaimer

>[!warning]
> This software is **for educational and personal use**. The developer is not responsible for misuse, data loss, or security breaches. Always use strong passwords and encryption keys responsibly.

## 🖥 GUI / Terminal Interface

* `tui` command provides a **terminal UI** to navigate tools interactively.
* Uses Ratatui library for cross-platform terminal rendering.
* You can extend it in the future for menus and tool selection.

## 🔮 Future Enhancements

* Case-insensitive commands.
* Support for more encodings (Hex, URL-safe Base64).
* More TUI features: menus, logging, copy-to-clipboard.
* File-based JSON and encryption pipelines.
* Web-based interface or Electron wrapper.

## 🔁 Flowchart

```
User Input
    │
    ▼
Clap Parser (Cli)
    │
    ├─> Command Matching
    │      ├─ Crypto (AES/HMAC/Hash)
    │      ├─ Encoding (Base64/Base32/URL)
    │      ├─ JSON/JWT
    │      ├─ Compression
    │      ├─ Random/Text
    │      └─ TUI/Completions
    │
    ▼
Execution
    │
    ▼
Output to Terminal / Files

```

## 💡 Key Concepts

* **CLI Utilities:** One command line program for multiple functions.
* **Subcommands:** Each tool has its own argument set.
* **Cross-platform:** Works on Windows, Linux, macOS.
* **Security-first:** Local cryptography, safe random generation.
* **Extensible:** Easily add new tools as subcommands.

## 🔑 Summary

* **Use:** Development, cryptography, encoding, random generation, text manipulation.
* **Value:** Saves time, local secure operations, single tool for multiple tasks.
* **Run:** Via Cargo, release build, or installed binary.
* **Important:** Use strong keys, avoid sharing sensitive data.

✅ **Developed by Syed Shaheer Hussain – 2026**

# Seclume: Secure File Archiving Tool - Linux

Seclume is a robust, command-line file archiving tool designed for secure archiving, encryption, and compression of files and directories. It combines **AES-256-GCM** encryption, **zlib DEFLATE** and **LZMA** compression, and **HMAC-SHA256** integrity protection to ensure confidentiality, integrity, and efficient storage of sensitive data. Seclume is ideal for users who prioritize security and need a reliable way to archive, encrypt, and extract files while preserving file permissions.

This document provides a comprehensive guide to Seclume's features, installation, usage, encryption logic, and technical details.

## Table of Contents

- [Features](#features)
- [Installation](#installation)
  - [Prerequisites](#prerequisites)
  - [Building from Source](#building-from-source)
- [Usage](#usage)
  - [Command-Line Options](#command-line-options)
  - [Modes](#modes)
    - [Archive Mode](#archive-mode)
    - [Extract Mode](#extract-mode)
    - [List Mode](#list-mode)
    - [View Comment](#view-comment)
  - [Examples](#examples)
- [Security Features](#security-features)
  - [Encryption](#encryption)
  - [Key Derivation](#key-derivation)
  - [Integrity Protection](#integrity-protection)
  - [Compression](#compression)
  - [Secure Randomization](#secure-randomization)
  - [File Permission Handling](#file-permission-handling)
- [Encryption Logic](#encryption-logic)
  - [Encryption Flow](#encryption-flow)
  - [ASCII Representation of Encryption Flow](#ascii-representation-of-encryption-flow)
- [Archive Format](#archive-format)
  - [Archive Header](#archive-header)
  - [File Entries](#file-entries)
- [Limitations](#limitations)
- [Error Handling](#error-handling)
- [Contributing](#contributing)
- [Reporting Bugs](#reporting-bugs)
- [License](#license)

## Features

Seclume provides the following key features:

- **Secure Encryption**: Uses **AES-256-GCM** for encrypting file data, metadata, and optional archive comments, ensuring confidentiality and authenticity.
- **Compression**: Employs **zlib DEFLATE** and **LZMA** with customizable compression levels (0-9) to reduce archive size.
- **Integrity Protection**: Computes **HMAC-SHA256** on the archive header to detect tampering.
- **Key Derivation**: Uses **PBKDF2** with SHA256 and 1,000,000 iterations for secure key derivation from passwords.
- **File Permission Preservation**: Stores and restores POSIX file permissions on Unix-like systems.
- **Recursive Directory Support**: Archives entire directory trees, with safeguards against path traversal attacks.
- **Archive Comments**: Allows adding encrypted comments to archives (up to 480 bytes after encryption overhead).
- **Dry Run Mode**: Simulates archiving operations without writing to disk, useful for testing.
- **Verbose Logging**: Supports multiple verbosity levels (`-vv` for debug, default for basic progress, or none for errors only).
- **Path Traversal Protection**: Prevents malicious filenames (e.g., containing `..`) from compromising security.
- **Password Strength Checking**: Ignoring weak passwords to encourage secure usage. unless **--weak-password** is specified.
- **User-Specified Directory Support**: Allows directing the archive or extracted files to different directories.
- **File-Type Exclusion**: Allows setting exceptions for file types during the archiving process.

## Installation

### Prerequisites

To build and run Seclume, you need the following dependencies:

- **C Compiler**: GCC, Clang, or any C99-compliant compiler.
- **OpenSSL**: Version 1.1.1 or later for AES-256-GCM encryption, PBKDF2, HMAC-SHA256, and secure random number generation.
- **zlib**: For DEFLATE compression and decompression (Fast compression, but may result in a larger file if the input data is already compressed or not compressible). 
- **lzma**: For compression and decompression (High compression, but may offer little to no size reduction if the input data is already compressed or not compressible).
- **Standard C Library**: For file operations and memory management.
- **Build Tools**: `make` and a compatible build system.

On Debian/Ubuntu-based systems, install the dependencies with:

```bash
sudo apt-get install build-essential libssl-dev zlib1g-dev liblzma-dev
```

On Red Hat/Fedora-based systems:

```bash
sudo dnf install gcc openssl-devel zlib-devel xz-devel
```

On macOS (using Homebrew):

```bash
brew install openssl zlib xz
```

### Building from Source

1. Clone or download the Seclume source code.
2. Navigate to the source directory:

   ```bash
   cd seclume
   ```

3. Compile the program using the provided `Makefile` (ensure OpenSSL and zlib are in your library path):

   ```bash
   make
   ```

4. Optionally, install the binary to `/usr/local/bin`:

   ```bash
   sudo make install
   ```

5. Verify the installation:

   ```bash
   seclume -h
   ```

If you encounter issues with OpenSSL or zlib, ensure the include and library paths are correctly set. For example:

```bash
export CFLAGS="-I/usr/local/openssl/include"
export LDFLAGS="-L/usr/local/openssl/lib"
make
```

## Usage

Seclume operates in three primary modes: **archive**, **extract**, and **list**, with optional flags to modify behavior. The general syntax is:

```bash
seclume [options] <mode> <archive.slm> <password> [files...]
```

### Command-Line Options

| Option | Description |
|--------|-------------|
| `-h`, `--help` | Displays the help message and exits. |
| `-vv` | Enables debug-level verbose output, showing detailed logging. |
| `-f` | Forces overwriting of existing files during archiving or extraction. |
| `-c`, `--comment <text>` | Adds a comment to the archive (archive mode only, max 480 bytes after encryption). |
| `-d`, `--dry-run` | Simulates archiving without writing to disk (archive mode only). |
| `-vc`, `--view-comment` | Displays the archive comment before executing the mode (not compatible with `-d` in archive mode). |
| `-ca`, `--compression-algo (zlib, lzma)` | Set compression algorithm (default = lzma). | 
| `-cl`, `--compression-level <0-9>` | Set compression level (0 = no, 9 = max, default = 1). |
| `-wk`, `--weak-password` | Allow weak passwords in archive mode (NOT RECOMMENDED). |
| `-o`, `--output-dir <dir>` | Specify output directory for extraction (archive/extract modes). |
| `-x`, `--exclude <patterns>` | Comma-separated file patterns to exclude during archiving (e.g., *.log,*.txt). |

### Modes

#### Archive Mode

Creates an encrypted `.slm` archive from specified files or directories.

```bash
seclume [options] archive <archive.slm> <password> <file1> [file2 ...]
```

- **Inputs**: One or more files or directories.
- **Output**: A `.slm` archive file containing compressed and encrypted data.
- **Behavior**:
  - Recursively archives directories.
  - Compresses files using zlib|lzma at the specified compression level.
  - Encrypts file data, metadata, and comments using AES-256-GCM.
  - Stores file permission.
  - Generates a random salt and nonces for encryption.
  - Computes an HMAC-SHA256 for the archive header.
- **Options Supported**: `-f`, `-c`, `-d`, `-vv`, `-ca`, `-cl`, `-wk`, `-o`, `-x`.

#### Extract Mode

Extracts and decrypts files from a `.slm` archive to the current directory.

```bash
seclume [options] extract <archive.slm> <password>
```

- **Inputs**: The `.slm` archive and the decryption password.
- **Output**: Extracted files with their original names and permissions.
- **Behavior**:
  - Verifies the archive header's HMAC.
  - Decrypts metadata and file data using AES-256-GCM.
  - Decompresses file data using zlib|lzma.
  - Restores POSIX file permissions (Unix-like systems).
  - Creates parent directories as needed.
- **Options Supported**: `-f`, `-vc`, `-vv`, `-o`.

#### List Mode

Lists the contents of a `.slm` archive without extracting files.

```bash
seclume [options] list <archive.slm> <password>
```

- **Inputs**: The `.slm` archive and the decryption password.
- **Output**: A table of file permissions, sizes, and filenames.
- **Behavior**:
  - Verifies the archive header's HMAC.
  - Decrypts metadata to display filenames, sizes, and permissions.
  - Skips file data, making it faster than extraction.
- **Options Supported**: `-vc`, `-vv`.

#### View Comment

Displays the encrypted comment in a `.slm` archive (if present). This is typically used with the `-vc` flag in extract or list modes but can be invoked standalone in the code.

```bash
seclume -vc list <archive.slm> <password>
```

- **Behavior**:
  - Reads and verifies the archive header.
  - Decrypts the comment (if present) using AES-256-GCM.
  - Prints the comment or indicates if none exists.

### Examples

1. **Create an archive with default compression**:

   ```bash
   seclume archive output.slm mypassWORD123! file1.txt dir/
   ```

   Archives `file1.txt` and the contents of `dir/` into `output.slm` with compression level 6.

2. **Create an archive with different compression algorithm and maximum compression level and a comment**:

   ```bash
   seclume --compression-algo lzma --compression-level 9 -c "My secure archive" archive output.slm mypassWORD123! dir/
   ```

   Uses maximum compression (level 9) and adds an encrypted comment.

3. **Perform a dry run to simulate archiving**:

   ```bash
   seclume -d archive output.slm mypassWORD123! file1.txt
   ```

   Simulates archiving without creating the output file.

4. **Extract an archive with overwrite**:

   ```bash
   seclume -f extract output.slm mypassWORD123!
   ```

   Extracts files, overwriting existing ones if necessary.

5. **List archive contents with verbose output**:

   ```bash
   seclume -vv list output.slm mypassWORD123!
   ```

   Lists files with detailed debug logging.

6. **View archive comment before listing**:

   ```bash
   seclume -vc list output.slm mypassWORD123!
   ```

   Displays the comment (if any) before listing the archive contents.

7. **Weak password handling**:

   ```bash
   seclume -wk archive output.slm mypassword file1.txt
   ```

   Forces Seclume to use a weak password.

8. **Placing the archive file in a different directory**:

   ```bash
   seclume -o /path/to/directory archive output.slm mypassWORD123! file1.txt dir/
   ```

   The `.slm` file is generated in the same directory where you run Seclume. But, when extracting it, the extracted files will be placed in the directory you specify.

9. **Excluding a specific file-type when archiving**:
   ```bash
   seclume -x *.log archive output.slm mypassWORD123! dir/
   ```

   It will skip all .log files when creating the archive.

## Security Features

Seclume is designed with security as a top priority. Below are its core security mechanisms:

### Encryption

- **Algorithm**: AES-256-GCM (Galois/Counter Mode) for authenticated encryption.
- **Scope**: Encrypts file data, metadata (filenames, sizes, permissions), and archive comments.
- **Nonce**: Uses 12-byte random nonces generated with OpenSSL's cryptographically secure `RAND_bytes`.
- **Authentication**: Produces a 16-byte authentication tag for each encrypted block to ensure data integrity and authenticity.

### Key Derivation

- **Algorithm**: PBKDF2 with SHA256 and 1,000,000 iterations.
- **Salt**: 16-byte random salt stored in the archive header.
- **Keys**: Derives two 32-byte AES-256 keys:
  - One for file data encryption.
  - One for metadata and comment encryption.
- **Purpose**: Strengthens weak passwords and prevents brute-force attacks.

### Integrity Protection

- **Algorithm**: HMAC-SHA256.
- **Scope**: Computes a 32-byte HMAC over the archive header (excluding the HMAC field itself).
- **Purpose**: Detects tampering or corruption of the archive header.

### Compression

- **Algorithm**: zlib and lzma.
- **Levels**: 0 (no compression) to 9 (maximum compression), default is 1.
- **Purpose**: Minimizes archive size using efficient compression while ensuring compatibility with both zlib-based tools and high-compression LZMA workflows.

### Secure Randomization

- **Source**: OpenSSL's `RAND_bytes` for cryptographically secure random numbers.
- **Usage**: Generates salts and nonces for encryption and key derivation.
- **Purpose**: Ensures unpredictability in cryptographic operations.

### File Permission Handling

- **Storage**: Captures POSIX file permissions (`st_mode`) during archiving.
- **Restoration**: Restores permissions during extraction using `chmod`.

## Encryption Logic

Seclume employs a robust encryption pipeline to ensure the confidentiality, integrity, and authenticity of archived data. The encryption process uses **AES-256-GCM** (Advanced Encryption Standard with 256-bit keys in Galois/Counter Mode), combined with **PBKDF2** for key derivation and **HMAC-SHA256** for integrity protection. Below is a detailed breakdown of the encryption logic:

### Encryption Flow

1. **Password-Based Key Derivation**:
   - **Input**: User-provided password and a 16-byte random salt generated using `RAND_bytes`.
   - **Process**: The password and salt are processed using **PBKDF2** with SHA256 and 1,000,000 iterations to derive two 32-byte AES-256 keys:
     - **File Key**: For encrypting file data.
     - **Metadata Key**: For encrypting metadata (filenames, sizes, permissions) and archive comments.
   - **Output**: Two secure keys resistant to brute-force attacks due to the high iteration count.
   - **Purpose**: Ensures that even weak passwords require significant computational effort to crack.

2. **Header Creation and Protection**:
   - **Input**: Archive metadata (magic string "SECLUME1", version, file count, compression level, comment length, salt).
   - **Process**:
     - The archive header is populated with metadata and the random salt.
     - An HMAC-SHA256 is computed over the header (excluding the HMAC field) using the file key.
     - If a comment is provided, it is encrypted with AES-256-GCM using the metadata key, a 12-byte random nonce, and a 16-byte authentication tag, then stored in the header.
   - **Output**: A tamper-proof header with an encrypted comment (if applicable).
   - **Purpose**: Protects the archive's metadata integrity and authenticity.

3. **File Compression**:
   - **Input**: Raw file data read from input files.
   - **Process**: Each file is compressed using **zlib DEFLATE** or **LZMA** with the user-specified compression level (0-9).
   - **Output**: Compressed file data, reducing storage requirements.
   - **Purpose**: Minimizes the archive size before encryption.

4. **File Data Encryption**:
   - **Input**: Compressed file data.
   - **Process**:
     - A 12-byte random nonce is generated for each file using `RAND_bytes`.
     - The compressed data is encrypted with AES-256-GCM using the file key, producing ciphertext and a 16-byte authentication tag.
   - **Output**: Encrypted file data with an authentication tag.
   - **Purpose**: Ensures confidentiality and integrity of file contents.

5. **Metadata Encryption**:
   - **Input**: File metadata (filename, compressed size, original size, permissions).
   - **Process**:
     - A 12-byte random nonce is generated for each file's metadata.
     - The metadata (stored in a `FileEntryPlain` structure) is encrypted with AES-256-GCM using the metadata key, producing encrypted metadata and a 16-byte authentication tag.
   - **Output**: Encrypted `FileEntry` structure containing the nonce, tag, and encrypted metadata.
   - **Purpose**: Protects sensitive metadata from unauthorized access.

6. **Archive Assembly**:
   - **Process**: The header, encrypted metadata, file nonces, file tags, and encrypted file data are written sequentially to the `.slm` archive file.
   - **Output**: A secure `.slm` archive.
   - **Purpose**: Combines all components into a single, secure file format.

7. **Decryption and Extraction**:
   - **Process**:
     - The header is read, and its HMAC is verified using the derived file key.
     - The comment (if present) is decrypted using the metadata key.
     - For each file:
       - The metadata is decrypted using the metadata key to retrieve the filename, sizes, and permissions.
       - The file data is decrypted using the file key and decompressed.
       - Files are written to disk with restored permissions (Unix-like systems).
   - **Purpose**: Ensures that only users with the correct password can access the archive's contents and verifies data integrity.

### ASCII Representation of Encryption Flow

Below is an ASCII diagram illustrating the encryption flow for creating a Seclume archive:

```
+-------------------+
| User Input        |
| - Password        |
| - Files/Dirs      |
| - Comment (opt)   |
| - Comp. Level     |
+-------------------+
          |
          v
+-------------------+
| Generate Salt     |
| (16 bytes, RAND)  |
+-------------------+
          |
          v
+-------------------+
| PBKDF2 (SHA256)   |
| - 1M iterations   |
| - Derive File Key |
| - Derive Meta Key |
+-------------------+
          |                 +------------------+
          v                 |                  |
+-------------------+       |                  v
| Create Header     |       |   +-----------------------------+
| - Magic, Version  |       |   | Compress File Data          |
| - File Count      |       |   | - Level: 0-9                |
| - Comp. Level     |       |   +-----------------------------+
| - Salt            |       |                  |
| - Comment (enc)   |<------+                  v
| - HMAC (file key) |       |   +-----------------------------+
+-------------------+       |   | Encrypt File Data (AES-256) |
          |                 |   | - File Key, 12-byte Nonce  |
          v                 |   | - 16-byte Auth Tag         |
+-------------------+       |   +-----------------------------+
| For Each File:    |       |                  |
| - Read Data       |       |                  v
| - Stat (size,     |       |   +-----------------------------+
|   permissions)    |       |   | Encrypt Metadata (AES-256)  |
+-------------------+       |   | - Meta Key, 12-byte Nonce  |
          |                 |   | - 16-byte Auth Tag         |
          v                 |   | - Filename, Sizes, Mode    |
+-------------------+       |   +-----------------------------+
| Write to Archive  |<------+                  |
| - Header          |                          v
| - File Entries    |       +-----------------------------+
| - File Nonces     |       | Write to .slm Archive File  |
| - File Tags       |       +-----------------------------+
| - Encrypted Data  |
+-------------------+
```

**Key Components**:
- **User Input**: Password, files, optional comment, compression algorithm, and compression level.
- **Salt Generation**: Random 16-byte salt for PBKDF2.
- **Key Derivation**: PBKDF2 produces two AES-256 keys.
- **Header**: Contains metadata and HMAC for integrity.
- **File Processing**: Compression, encryption of data and metadata.
- **Archive**: Combines all components into a `.slm` file.

The decryption process mirrors this flow in reverse, starting with HMAC verification, key derivation, and sequential decryption and decompression.

## Archive Format

The `.slm` archive format is structured as follows:

### Archive Header

| Field | Size (Bytes) | Description |
|-------|--------------|-------------|
| `magic` | 3 | "SLM" identifier. |
| `version` | 1 | Archive format version (1, 2, or 3). |
| `file_count` | 4 | Number of files in the archive. |
| `compression_algorithm` | 5 | Compression algorithm (zlib, lzma). | 
| `compression_level` | 1 | Compression level (0-9, version 2+). |
| `comment_len` | 4 | Length of encrypted comment (version 3+). |
| `reserved` | 3 | Zeroed for future use. |
| `salt` | 16 | Random salt for PBKDF2. |
| `comment` | 512 | Encrypted comment, nonce, and tag (version 3+). |
| `hmac` | 32 | HMAC-SHA256 of the header (excluding this field). |

### File Entries

Each file in the archive consists of:

1. **FileEntry Structure**:
   - `nonce` (12 bytes): Nonce for metadata encryption.
   - `tag` (16 bytes): Authentication tag for metadata.
   - `encrypted_data` (size of `FileEntryPlain`): Encrypted filename, sizes, and permissions.

2. **File Nonce** (12 bytes): Nonce for file data encryption.
3. **File Tag** (16 bytes): Authentication tag for file data.
4. **Encrypted File Data**: Compressed file data encrypted with AES-256-GCM.

The `FileEntryPlain` structure (decrypted metadata) contains:

| Field | Size (Bytes) | Description |
|-------|--------------|-------------|
| `filename` | 256 | Null-terminated filename. |
| `compressed_size` | 8 | Size of compressed and encrypted file data. |
| `original_size` | 8 | Original file size before compression. |
| `mode` | 4 | POSIX file permissions (version 2+). |
| `reserved` | 4 | Zeroed for future use. |

## Limitations

- **Maximum File Size**: 10GB per file (`MAX_FILE_SIZE`).
- **Maximum Files**: 1000 files per archive (`MAX_FILES`).
- **Maximum Comment Length**: 480 bytes (after encryption overhead).
- **No Incremental Updates**: Archives cannot be modified; they must be recreated.

## Error Handling

Seclume provides detailed error messages for various failure conditions, including:

- **Invalid Parameters**: Checks for null pointers, empty files, or invalid compression levels.
- **File Access Errors**: Reports issues opening or reading files (`errno` details included).
- **Cryptographic Failures**: Handles encryption, decryption, and key derivation errors.
- **Path Traversal**: Rejects filenames with `..` sequences.
- **Archive Corruption**: Detects invalid headers, versions, or HMAC mismatches.
- **Memory Allocation**: Reports failures to allocate buffers.
- **Weak Passwords**: Strict about short or low-variety passwords only allows archiving when `-wk` is specified.

Verbose mode (`-vv`) provides additional debug output, including timestamps and file data snippets.

## Reporting Bugs

Report bugs to **lone_kuroshiro@protonmail.com**. When reporting, include:

- Seclume version (1.0.5).
- Steps to reproduce the issue.
- Relevant error messages or logs (use `-vv` for detailed output).

## License

Seclume is provided under BSD 3-Clause [License](https://github.com/kUrOSH1R0oo/Seclume/blob/main/LICENSE). Contact the maintainer for licensing details.



<!--
SPDX-FileCopyrightText: 2024 Winni Neessen <wn@neessen.dev>

SPDX-License-Identifier: MIT
-->

# dbenc

[![GoDoc](https://godoc.org/github.com/wneessen/dbenc?status.svg)](https://pkg.go.dev/github.com/wneessen/dbenc)
[![codecov](https://codecov.io/gh/wneessen/dbenc/branch/main/graph/badge.svg?token=37KWJV03MR)](https://codecov.io/gh/wneessen/dbenc)
[![Go Report Card](https://goreportcard.com/badge/github.com/wneessen/dbenc)](https://goreportcard.com/report/github.com/wneessen/dbenc)
[![REUSE status](https://api.reuse.software/badge/github.com/wneessen/dbenc)](https://api.reuse.software/info/github.com/wneessen/dbenc)
<a href="https://ko-fi.com/D1D24V9IX"><img src="https://uploads-ssl.webflow.com/5c14e387dab576fe667689cf/5cbed8a4ae2b88347c06c923_BuyMeACoffee_blue.png" height="20" alt="buy ma a coffee"></a>

`dbenc` provides a secure and efficient way to encrypt and decrypt Go data structures for storage in databases.
Leveraging Go’s `gob` encoding format, it serializes complex data structures before encryption, making it well-suited
for handling structs, slices, maps, and other structured data.

## Features

- **Secure encryption** using an authenticated encryption with additional data (AEAD) cipher like `AES-GCM` or
  `ChaCha20-Poly1305`.
- **Data integrity verification** to ensure encrypted data is not tampered with.
- **Support for complex Go data structures** (e.g., structs, slices, maps) through `gob` encoding.

## Installation

```bash
$ go get github.com/wneessen/dbenc
```

## Threat Model and AAD Usage

`dbenc` is designed to protect sensitive data in databases from tampering and unauthorized reuse. Specifically, it
addresses threats where an attacker might attempt to swap encrypted values between rows or tables, or reuse encrypted
data in unintended contexts.

To prevent these attacks, `dbenc` encourages the use of **Additional Authenticated Data (AAD)**, binding encrypted data
to its specific context (e.g., table name, row ID, column name). This ensures that encrypted values are valid only in
their original context and cannot be swapped or reused by an adversary without detection.

## Warnings and Limitations

### Gob Decoder

The `gob` package is designed to serialize and deserialize Go data structures efficiently, but it does not include
protections against malicious or adversarial data inputs. Decoding data from untrusted sources using gob can potentially
consume significant resources, as the Decoder does only basic sanity checks on decoded input sizes, and its limits are
not configurable.

For this reason, only decode gob data from trusted sources to avoid unintended resource consumption or other
vulnerabilities that might arise from handling adversarial inputs.

### Performance and Efficiency

While dbenc provides flexible encryption for complex data structures, its reliance on gob serialization and in-memory
buffering may lead to inefficiencies when handling very large data or high-throughput workloads. Serializing complex
structures with gob can be memory-intensive, and encryption operations may impose additional CPU load.

For applications requiring efficient handling of large data sets or high performance under heavy load, consider
benchmarking and profiling the code to assess its performance in your specific use case.

## Example

### En- and decrypt a strcut with AAD
```go
package main

import (
    "crypto/aes"
    "crypto/cipher"
    "log"
    
    "github.com/wneessen/dbenc"
)

func main() {
    key := []byte("your-32-byte-key-here-12345678901234")
    block, err := aes.NewCipher(key)
    if err != nil {
        log.Fatalf("Failed to create cipher: %v", err)
    }
    aead, err := cipher.NewGCM(block)
    if err != nil {
        log.Fatalf("Failed to create AEAD: %v", err)
    }

    encryptor := dbenc.New(aead)
    myData := struct{ Name string }{"example"}

    // Define AAD with contextual information
    tableName := "users"
    rowID := "12345"
    columnName := "name"
    authData := []byte(tableName + ":" + rowID + ":" + columnName)

    // Encrypt with contextual AAD
    encryptedData, err := encryptor.Encrypt(myData, authData)
    if err != nil {
        log.Fatalf("Encryption failed: %v", err)
    }

    // Decrypt with the same contextual AAD
    var decryptedData struct{ Name string }
    err = encryptor.Decrypt(&decryptedData, encryptedData, authData)
    if err != nil {
        log.Fatalf("Decryption failed: %v", err)
    }
    
    log.Printf("Decrypted data: %+v", decryptedData)
}
```

## License

This package is licensed under the MIT License. See [LICENSE](LICENSE) for details.

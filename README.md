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

`dbenc` provides a secure and efficient way to encrypt and decrypt Go data structures for storage in databases. Leveraging Go’s `gob` encoding format, it serializes complex data structures before encryption, making it well-suited for handling structs, slices, maps, and other structured data.

## Features

- **Secure encryption** using an authenticated encryption with additional data (AEAD) cipher like `AES-GCM` or `ChaCha20-Poly1305`.
- **Data integrity verification** to ensure encrypted data is not tampered with.
- **Support for complex Go data structures** (e.g., structs, slices, maps) through `gob` encoding.

## Installation

```bash
$ go get github.com/wneessen/dbenc
```

## Example
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

    encryptedData, err := encryptor.Encrypt(myData, []byte("authData"))
    if err != nil {
        log.Fatalf("Encryption failed: %v", err)
    }

    var decryptedData struct{ Name string }
    err = encryptor.Decrypt(&decryptedData, encryptedData, []byte("authData"))
    if err != nil {
        log.Fatalf("Decryption failed: %v", err)
    }
    
    log.Printf("Decrypted data: %+v", decryptedData)
}
```

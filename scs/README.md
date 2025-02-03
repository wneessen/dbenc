# scs
TODO: WORK IN PROGRESS
## Overview

The `scs` package provides an implementation of the Codec interface for [Alex Edwards' SCS Session Management](https://github.com/alexedwards/scs). It enables the use of [dbenc](https://github.com/wneessen/dbenc) to encrypt session data before storing them in memory or any other supported SCS session storage.

## Features

- Implements `scs.Codec` interface for seamless integration with SCS.
- Encrypts session data using `dbenc` before storage.
- Secure serialization and deserialization of session values.

## Installation

To install the package, run:

```sh
go get github.com/yourusername/scs
```

## Usage

### Importing

```go
import (
    "crypto/cipher"
    "github.com/yourusername/scs"
    "github.com/wneessen/dbenc"
)
```

### Creating a New Codec

To initialize a new `Codec` instance, provide an AEAD cipher:

```go
func initializeCodec(aead cipher.AEAD) *scs.Codec {
    return scs.New(aead)
}
```

### Encoding Session Data

```go
sessionData := map[string]interface{}{
    "user_id": 12345,
    "username": "testuser",
}
deadline := time.Now().Add(24 * time.Hour) // 24-hour expiration

ciphertext, err := codec.Encode(deadline, sessionData)
if err != nil {
    log.Fatalf("Error encoding session: %v", err)
}
```

### Decoding Session Data

```go
decodedDeadline, decodedValues, err := codec.Decode(ciphertext)
if err != nil {
    log.Fatalf("Error decoding session: %v", err)
}
fmt.Printf("Session expires at: %v, Data: %v", decodedDeadline, decodedValues)
```

## API Reference

### `New`

```go
func New(aead cipher.AEAD) *Codec
```

Creates and returns a new `Codec` instance initialized with the given AEAD cipher.

### `Encode`

```go
func (c Codec) Encode(deadline time.Time, values map[string]interface{}) ([]byte, error)
```

Encodes and encrypts session data before storage.

### `Decode`

```go
func (c Codec) Decode(ciphertext []byte) (time.Time, map[string]interface{}, error)
```

Decrypts and decodes session data, restoring the original session values.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
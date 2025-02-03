# dbenc - SCS Codec Interface

## Overview

The `scs` package provides an implementation of the Codec interface
for [Alex Edwards' SCS: HTTP Session Management](https://github.com/alexedwards/scs). It enables the use
of [dbenc](https://github.com/wneessen/dbenc) to encrypt session data before storing them in any 
supported SCS session storage.

## Usage

### Importing

```go
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"log"
	"net/http"

	"github.com/alexedwards/scs/v2"
	"github.com/wneessen/dbenc/scs"
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

	// Initialize a new session manager and set dbenc as Codec
	sessionManager = scs.New()
	sessionManager.Codec = scs_codec.New(aead)

	mux := http.NewServeMux()
	mux.HandleFunc("/sessoin", yourSessionHandler)
	http.ListenAndServe(":4000", sessionManager.LoadAndSave(mux))
}
```

## License

This package is licensed under the MIT License. See [LICENSE](LICENSE) for details.

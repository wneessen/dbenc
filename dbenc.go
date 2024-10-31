// SPDX-FileCopyrightText: 2024 Winni Neessen <wn@neessen.dev>
//
// SPDX-License-Identifier: MIT

// Package dbenc provides a secure and efficient way to encrypt and decrypt Go data
// structures for storage in databases. It leverages Go’s gob encoding format to
// serialize complex data structures before encryption, making it especially suitable
// for handling structured data like structs, slices, and maps.
//
// This package is designed for applications that require secure, authenticated
// encryption of data.
package dbenc

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/gob"
	"errors"
	"fmt"
	"io"
)

var (
	// ErrNilPtr is an error indicating that a nil pointer was provided where a valid pointer was expected.
	ErrNilPtr = errors.New("provided value is nil")

	// ErrNoCipher is an error indicating that a cipher value is missing or nil when it is required.
	ErrNoCipher = errors.New("cipher is nil")

	// ErrCiphertextTooShort indicates that the provided ciphertext is shorter than the required length.
	ErrCiphertextTooShort = errors.New("ciphertext too short")
)

// Encryptor provides encryption and decryption capabilities using an
// authenticated encryption with additional data (AEAD) cipher. This struct
// enables secure encryption with integrity verification, ensuring that the
// encrypted data has not been tampered with.
//
// Fields:
//   - cipher (cipher.AEAD): An AEAD cipher used to perform the encryption
//     and decryption. The cipher must be initialized before use, and it provides
//     both confidentiality and authenticity for the data.
//
// Usage:
// The Encryptor struct is designed for encrypting sensitive data that needs
// to be securely stored. It can be used in conjunction with additional functions
// that handle encoding and decoding, making it suitable for complex data structures.
type Encryptor struct {
	cipher cipher.AEAD
}

// New creates a new Encryptor instance using the provided AEAD cipher for
// encryption and decryption. This function allows initializing an Encryptor
// with a specific AEAD cipher, enabling secure and authenticated encryption
// capabilities.
//
// Parameters:
//   - aead cipher.AEAD: The AEAD cipher used for encryption and decryption.
//     This cipher must be properly initialized before calling New.
//
// Returns:
//   - Encryptor: An Encryptor instance configured with the given AEAD cipher,
//     ready to perform encryption and decryption operations.
//
// Example:
//
//	aeadCipher := ... // Initialize your AEAD cipher (e.g., with AES-GCM or ChaCha20-Poly1305)
//	encryptor := New(aeadCipher)
//	encryptedData, err := encryptor.Encrypt(plainData, authData)
//	if err != nil {
//	    log.Fatalf("encryption failed: %v", err)
//	}
func New(aead cipher.AEAD) Encryptor {
	return Encryptor{
		cipher: aead,
	}
}

// Encrypt serializes the given data and encrypts it using the provided
// authentication data. This method encodes the `data` using the gob format,
// ensuring that complex Go data structures can be serialized before encryption.
// The resulting encrypted byte slice is suitable for secure storage or transmission.
//
// Parameters:
//   - data (any): The data to be encrypted. It can be any serializable Go type,
//     such as structs, slices, maps, etc.
//   - authData ([]byte): Additional authentication data used for encrypting
//     the serialized data. This can be used to add an additional layer of security
//     (e.g., for AES-GCM encryption).
//
// Returns:
//   - []byte: A byte slice containing the encrypted form of the serialized data.
//   - error:  An error if serialization or encryption fails.
//
// Example Usage:
//
//	encryptedData, err := dbEncrypter.Encrypt(myData, myAuthData)
//	if err != nil {
//	    log.Fatalf("encryption failed: %v", err)
//	}
//
// Errors:
//   - Returns an error if the data cannot be encoded using gob encoding.
//   - Returns an error if encryption fails within the `encrypt` method.
func (e Encryptor) Encrypt(data any, authData []byte) ([]byte, error) {
	buffer := bytes.NewBuffer(nil)
	encoder := gob.NewEncoder(buffer)
	if err := encoder.Encode(data); err != nil {
		return nil, fmt.Errorf("failed to encode data: %w", err)
	}
	return e.encrypt(buffer.Bytes(), authData)
}

// Decrypt decrypts the provided ciphertext using the specified authentication data
// and deserializes the decrypted data into the `dst` variable. The function expects
// the decrypted data to be in gob format, making it suitable for complex Go data
// structures that were originally serialized with gob encoding.
//
// Parameters:
//   - dst (any): A pointer to the variable where the decrypted data will be stored.
//     `dst` must be a pointer to a Go data structure (e.g., a struct, slice, map) that
//     matches the type used during encryption. If `dst` is nil, an error is returned.
//   - ciphertext ([]byte): The encrypted byte slice containing the data to be decrypted.
//   - authData ([]byte): The authentication data used during encryption; it must
//     match the data used in the original encryption to enable successful decryption.
//
// Returns:
//   - error: Returns an error if decryption or decoding fails, or if `dst` is nil.
//
// Example Usage:
//
//	var myData MyStruct
//	err := dbEncrypter.Decrypt(&myData, encryptedData, myAuthData)
//	if err != nil {
//	    log.Fatalf("decryption failed: %v", err)
//	}
//
// Errors:
//   - Returns `ErrNilPtr` if `dst` is nil, indicating a nil pointer for the destination.
//   - Returns an error if decryption fails within the `decrypt` method.
//   - Returns an error if decoding the gob-encoded data fails, with additional context.
//
// Notes:
//   - The `dst` parameter must be a pointer, as it will be populated with the decoded
//     data upon successful decryption.
func (e Encryptor) Decrypt(dst any, ciphertext, authData []byte) error {
	if dst == nil {
		return ErrNilPtr
	}
	data, err := e.decrypt(ciphertext, authData)
	if err != nil {
		return fmt.Errorf("failed to decrypt data: %w", err)
	}
	buffer := bytes.NewBuffer(data)
	decoder := gob.NewDecoder(buffer)
	if err = decoder.Decode(dst); err != nil {
		return fmt.Errorf("failed to decode data: %w", err)
	}
	return err
}

// encrypt is the underlying encryption method
func (e Encryptor) encrypt(data, authData []byte) ([]byte, error) {
	if e.cipher == nil {
		return nil, ErrNoCipher
	}
	nonce := make([]byte, e.cipher.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate random iv: %w", err)
	}
	cipherText := e.cipher.Seal(nonce, nonce, data, authData)
	return cipherText, nil
}

// decrypt is the underlying decyption method
func (e Encryptor) decrypt(data, authData []byte) ([]byte, error) {
	if e.cipher == nil {
		return nil, ErrNoCipher
	}
	if len(data) < e.cipher.NonceSize() {
		return nil, ErrCiphertextTooShort
	}
	nonce, ciphertext := data[:e.cipher.NonceSize()], data[e.cipher.NonceSize():]
	return e.cipher.Open(nil, nonce, ciphertext, authData)
}

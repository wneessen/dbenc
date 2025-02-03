// SPDX-FileCopyrightText: Winni Neessen <wn@neessen.dev>
//
// SPDX-License-Identifier: MIT

// Package scs_codec implements the Codec interface of Alex Edward's SCS Session Management
// package so that dbenc can be used for encrypting session data before storing them
// in memory or in any other corrsponding session storage that is supported by SCS.
//
// Due to the nature of the interface, dbenc will not authenticate the encrypted data
// since it has no value that could be used for the corresponding authentication.

package scs_codec

import (
	"bytes"
	"crypto/cipher"
	"encoding/gob"
	"fmt"
	"time"

	"github.com/wneessen/dbenc"
)

// Codec provides encoding and decoding functionality for securely storing
// session data. It satisfies the scs.Codec interface and uses dbenc as base
// for the encryption and decryption process.
type Codec struct {
	encrypter dbenc.Encryptor
}

// New initializes and returns a new Codec instance using the provided AEAD
// cipher for encryption.
//
// Parameters:
//   - aead (cipher.AEAD): An AEAD cipher used to initialize the encryption
//     mechanism.
//
// Returns:
//   - Codec: A new pointer to an instance of Codec configured with the provided
//     AEAD cipher.
func New(aead cipher.AEAD) *Codec {
	enc := dbenc.New(aead)
	return &Codec{
		encrypter: enc,
	}
}

// Encode serializes and encrypts session data, ensuring secure storage.
//
// Parameters:
//   - deadline (time.Time): The expiration time of the session data.
//   - values (map[string]interface{}): The session values to be encoded and encrypted.
//
// Returns:
//   - []byte: The encrypted session data.
//   - error: An error if encoding or encryption fails.
//
// The function first serializes the input data using gob encoding, then encrypts it using
// the underlying dbenc encryption mechanism.
func (c Codec) Encode(deadline time.Time, values map[string]interface{}) ([]byte, error) {
	aux := &struct {
		Deadline time.Time
		Values   map[string]interface{}
	}{
		Deadline: deadline,
		Values:   values,
	}

	buffer := bytes.NewBuffer(nil)
	if err := gob.NewEncoder(buffer).Encode(aux); err != nil {
		return nil, fmt.Errorf("failed to encode session data: %w", err)
	}

	ciphertext, err := c.encrypter.Encrypt(buffer.Bytes(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt session data: %w", err)
	}
	return ciphertext, nil
}

// Decode decrypts and deserializes session data, restoring the original values.
//
// Parameters:
//   - ciphertext ([]byte): The encrypted session data to be decrypted and decoded.
//
// Returns:
//   - time.Time: The original session expiration time.
//   - map[string]interface{}: The restored session values.
//   - error: An error if decryption or decoding fails.
//
// The function decrypts the given ciphertext using dbenc and deserializes it back
// into its structured session representation.
func (c Codec) Decode(ciphertext []byte) (time.Time, map[string]interface{}, error) {
	aux := &struct {
		Deadline time.Time
		Values   map[string]interface{}
	}{}

	var plaintext []byte
	if err := c.encrypter.Decrypt(&plaintext, ciphertext, nil); err != nil {
		return time.Time{}, nil, fmt.Errorf("failed to decrypt session data: %w", err)
	}

	reader := bytes.NewReader(plaintext)
	if err := gob.NewDecoder(reader).Decode(&aux); err != nil {
		return time.Time{}, nil, fmt.Errorf("failed to decode session data: %w", err)
	}

	return aux.Deadline, aux.Values, nil
}

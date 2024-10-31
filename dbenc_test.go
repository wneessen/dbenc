// SPDX-FileCopyrightText: 2024 Winni Neessen <wn@neessen.dev>
//
// SPDX-License-Identifier: MIT

package dbenc

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"strings"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

var (
	testKey256 = []byte{
		0xbf, 0x8b, 0x34, 0xf7, 0x7d, 0x5c, 0x44, 0x7e, 0xbf, 0x56, 0x16, 0x34, 0x27, 0x97, 0x60, 0x27,
		0xfd, 0x30, 0xa6, 0xa2, 0x40, 0x76, 0xd4, 0x53, 0xec, 0x58, 0xe3, 0xb8, 0x60, 0xd1, 0x10, 0xdd,
	}
	testKey128 = []byte{
		0xd3, 0xfc, 0xe3, 0x8c, 0xa3, 0xc8, 0xfd, 0x44, 0x37, 0x60, 0x65, 0x7f, 0x85, 0x9d, 0xba, 0x33,
	}
)

func TestEncryptor_New(t *testing.T) {
	tests := []struct {
		name string
		aead cipher.AEAD
	}{
		{"AES-256-GCM", getTestAEADCipher(t, "aes", testKey256)},
		{"AES-128-GCM", getTestAEADCipher(t, "aes", testKey128)},
		{"ChaCha20-Poly1305", getTestAEADCipher(t, "chacha20", testKey256)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encryptor := New(tt.aead)
			if encryptor.cipher != tt.aead {
				t.Fatalf("expected cipher to be set")
			}
		})
	}
	t.Run("Nil cipher", func(t *testing.T) {
		encryptor := New(nil)
		if encryptor.cipher != nil {
			t.Fatalf("expected cipher to be nil")
		}
		_, err := encryptor.Encrypt("test data", []byte("auth data"))
		if err == nil {
			t.Fatalf("encryptor with nil cipher should fail")
		}
		if !errors.Is(err, ErrNoCipher) {
			t.Errorf("expected ErrNoCipher, got %s", err)
		}
	})
}

func TestEncryptor_Encrypt(t *testing.T) {
	type testType struct {
		String    string
		Int       int
		Bool      bool
		UInt      uint
		Bytes     []byte
		StringMap map[string]string
	}
	data := testType{
		String:    "test",
		Int:       42,
		Bool:      true,
		UInt:      666,
		Bytes:     []byte("Bytes"),
		StringMap: map[string]string{"answer": "42 is the answer to life, the universe and everything"},
	}
	tests := []struct {
		name string
		aead cipher.AEAD
	}{
		{"AES-256-GCM", getTestAEADCipher(t, "aes", testKey256)},
		{"AES-128-GCM", getTestAEADCipher(t, "aes", testKey128)},
		{"ChaCha20-Poly1305", getTestAEADCipher(t, "chacha20", testKey256)},
	}
	for _, tt := range tests {
		t.Run(tt.name+" succeeds", func(t *testing.T) {
			encryptor := New(tt.aead)
			ciphertext, err := encryptor.Encrypt(data, []byte("auth data"))
			if err != nil {
				t.Fatalf("encryption failed: %v", err)
			}
			var plaindata testType
			err = encryptor.Decrypt(&plaindata, ciphertext, []byte("auth data"))
			if err != nil {
				t.Fatalf("decryption failed: %v", err)
			}
			if !plaindata.Bool {
				t.Errorf("expected Bool to be true, got false")
			}
			if plaindata.Int != 42 {
				t.Errorf("expected Int to be 42, got %d", plaindata.Int)
			}
			if plaindata.String != "test" {
				t.Errorf("expected String to be 'test', got '%s'", plaindata.String)
			}
			if plaindata.UInt != 666 {
				t.Errorf("expected UInt to be 666, got %d", plaindata.UInt)
			}
			if plaindata.Bytes[0] != 'B' {
				t.Errorf("expected Bytes[0] to be 'B', got '%c'", plaindata.Bytes[0])
			}
			if string(plaindata.Bytes) != "Bytes" {
				t.Errorf("expected Bytes to be 'Bytes', got '%s'", plaindata.Bytes)
			}
			if plaindata.StringMap["answer"] != "42 is the answer to life, the universe and everything" {
				t.Errorf("expected StringMap['answer'] to be '42 is the answer to life, the "+
					"universe and everything', got '%s'", plaindata.StringMap["answer"])
			}
		})
		t.Run(tt.name+" fails on encode", func(t *testing.T) {
			unexported := struct {
				unexported string
			}{unexported: "unexported"}
			encryptor := New(tt.aead)
			_, err := encryptor.Encrypt(unexported, nil)
			if err == nil {
				t.Fatalf("expected gob to fail on unexported field")
			}
			if !strings.Contains(err.Error(), "gob: type struct { unexported string } has no exported fields") {
				t.Errorf("expected error to be %q, got '%q'",
					"gob: type struct { unexported string } has no exported fields", err)
			}
		})
	}
}

func TestEncryptor_Decrypt(t *testing.T) {
	tests := []struct {
		name string
		aead cipher.AEAD
	}{
		{"AES-256-GCM", getTestAEADCipher(t, "aes", testKey256)},
		{"AES-128-GCM", getTestAEADCipher(t, "aes", testKey128)},
		{"ChaCha20-Poly1305", getTestAEADCipher(t, "chacha20", testKey256)},
	}
	for _, tt := range tests {
		t.Run(tt.name+" succeeds (no auth data)", func(t *testing.T) {
			encryptor := New(tt.aead)
			ciphertext, err := encryptor.Encrypt("this is a test", nil)
			if err != nil {
				t.Fatalf("encryption failed: %s", err)
			}
			var plaintext string
			if err = encryptor.Decrypt(&plaintext, ciphertext, nil); err != nil {
				t.Fatalf("decryption failed: %s", err)
			}
			if !strings.EqualFold(plaintext, "this is a test") {
				t.Errorf("expected plaintext to be 'this is a test', got '%s'", plaintext)
			}
		})
		t.Run(tt.name+" succeeds (with auth data)", func(t *testing.T) {
			encryptor := New(tt.aead)
			ciphertext, err := encryptor.Encrypt("this is a test", []byte("auth data"))
			if err != nil {
				t.Fatalf("encryption failed: %s", err)
			}
			var plaintext string
			if err = encryptor.Decrypt(&plaintext, ciphertext, []byte("auth data")); err != nil {
				t.Fatalf("decryption failed: %s", err)
			}
			if !strings.EqualFold(plaintext, "this is a test") {
				t.Errorf("expected plaintext to be 'this is a test', got '%s'", plaintext)
			}
		})
		t.Run(tt.name+" fails with wrong auth data (data vs. nil)", func(t *testing.T) {
			encryptor := New(tt.aead)
			ciphertext, err := encryptor.Encrypt("this is a test", []byte("auth data"))
			if err != nil {
				t.Fatalf("encryption failed: %s", err)
			}
			var plaintext string
			err = encryptor.Decrypt(&plaintext, ciphertext, nil)
			if err == nil {
				t.Errorf("expected decryption to fail with wrong auth data")
			}
			if !strings.Contains(err.Error(), "message authentication failed") {
				t.Errorf("expected error to be 'message authentication failed', got '%s'",
					err.Error())
			}
		})
		t.Run(tt.name+" fails with wrong auth data (nil vs. data)", func(t *testing.T) {
			encryptor := New(tt.aead)
			ciphertext, err := encryptor.Encrypt("this is a test", nil)
			if err != nil {
				t.Fatalf("encryption failed: %s", err)
			}
			var plaintext string
			err = encryptor.Decrypt(&plaintext, ciphertext, []byte("auth data"))
			if err == nil {
				t.Errorf("expected decryption to fail with wrong auth data")
			}
			if !strings.Contains(err.Error(), "message authentication failed") {
				t.Errorf("expected error to be 'message authentication failed', got '%s'",
					err.Error())
			}
		})
		t.Run(tt.name+" fails with wrong auth data (data1 vs. data2)", func(t *testing.T) {
			encryptor := New(tt.aead)
			ciphertext, err := encryptor.Encrypt("this is a test", []byte("auth data1"))
			if err != nil {
				t.Fatalf("encryption failed: %s", err)
			}
			var plaintext string
			err = encryptor.Decrypt(&plaintext, ciphertext, []byte("auth data2"))
			if err == nil {
				t.Errorf("expected decryption to fail with wrong auth data")
			}
			if !strings.Contains(err.Error(), "message authentication failed") {
				t.Errorf("expected error to be 'message authentication failed', got '%s'",
					err.Error())
			}
		})
		t.Run(tt.name+" fails with corrupted ciphertext (no auth data)", func(t *testing.T) {
			encryptor := New(tt.aead)
			ciphertext, err := encryptor.Encrypt("this is a test", nil)
			if err != nil {
				t.Fatalf("encryption failed: %s", err)
			}
			ciphertext[0] ^= 0x01
			var plaintext string
			err = encryptor.Decrypt(&plaintext, ciphertext, nil)
			if err == nil {
				t.Errorf("expected decryption to fail with corrupted ciphertext")
			}
			if !strings.Contains(err.Error(), "message authentication failed") {
				t.Errorf("expected error to be 'message authentication failed', got '%s'",
					err.Error())
			}
		})
		t.Run(tt.name+" fails with corrupted ciphertext (with auth data)", func(t *testing.T) {
			encryptor := New(tt.aead)
			ciphertext, err := encryptor.Encrypt("this is a test", []byte("auth data"))
			if err != nil {
				t.Fatalf("encryption failed: %s", err)
			}
			ciphertext[0] ^= 0x01
			var plaintext string
			err = encryptor.Decrypt(&plaintext, ciphertext, []byte("auth data"))
			if err == nil {
				t.Errorf("expected decryption to fail with corrupted ciphertext")
			}
			if !strings.Contains(err.Error(), "message authentication failed") {
				t.Errorf("expected error to be 'message authentication failed', got '%s'",
					err.Error())
			}
		})
		t.Run(tt.name+" fails with nil as dst pointer", func(t *testing.T) {
			encryptor := New(tt.aead)
			ciphertext, err := encryptor.Encrypt("this is a test", []byte("auth data"))
			if err != nil {
				t.Fatalf("encryption failed: %s", err)
			}
			err = encryptor.Decrypt(nil, ciphertext, []byte("auth data"))
			if err == nil {
				t.Errorf("expected decryption to fail with wrong auth data")
			}
			if !errors.Is(err, ErrNilPtr) {
				t.Errorf("expected error to be %q, got '%q'", ErrNilPtr, err)
			}
		})
		t.Run(tt.name+" fails with dst not a pointer", func(t *testing.T) {
			encryptor := New(tt.aead)
			ciphertext, err := encryptor.Encrypt("this is a test", []byte("auth data"))
			if err != nil {
				t.Fatalf("encryption failed: %s", err)
			}
			var plaintext string
			err = encryptor.Decrypt(plaintext, ciphertext, []byte("auth data"))
			if err == nil {
				t.Errorf("expected decryption to fail with wrong auth data")
			}
			if !strings.Contains(err.Error(), "gob: attempt to decode into a non-pointer") {
				t.Errorf("expected error to be 'gob: attempt to decode into a non-pointer', got '%s'",
					err.Error())
			}
		})
		t.Run(tt.name+" fails with dst is wrong type", func(t *testing.T) {
			encryptor := New(tt.aead)
			ciphertext, err := encryptor.Encrypt("this is a test", []byte("auth data"))
			if err != nil {
				t.Fatalf("encryption failed: %s", err)
			}
			var plaintext int
			err = encryptor.Decrypt(&plaintext, ciphertext, []byte("auth data"))
			if err == nil {
				t.Errorf("expected decryption to fail with wrong auth data")
			}
			if !strings.Contains(err.Error(), "gob: decoding into local type *int, received remote type string") {
				t.Errorf("expected error to be 'gob: decoding into local type *int, received remote type string', got '%s'",
					err.Error())
			}
		})
	}
}

func TestEncryptor_decrypt(t *testing.T) {
	tests := []struct {
		name string
		aead cipher.AEAD
	}{
		{"AES-256-GCM", getTestAEADCipher(t, "aes", testKey256)},
		{"AES-128-GCM", getTestAEADCipher(t, "aes", testKey128)},
		{"ChaCha20-Poly1305", getTestAEADCipher(t, "chacha20", testKey256)},
	}
	for _, tt := range tests {
		t.Run(tt.name+" fails with too short data", func(t *testing.T) {
			encryptor := New(tt.aead)
			_, err := encryptor.decrypt([]byte{0x01}, nil)
			if err == nil {
				t.Errorf("expected decryption to fail with too short data")
			}
			if !errors.Is(err, ErrCiphertextTooShort) {
				t.Errorf("expected error to be %q, got '%q'", ErrCiphertextTooShort, err)
			}
		})
		t.Run(tt.name+" fails with nil data", func(t *testing.T) {
			encryptor := New(tt.aead)
			_, err := encryptor.decrypt(nil, nil)
			if err == nil {
				t.Errorf("expected decryption to fail with nil data")
			}
			if !errors.Is(err, ErrCiphertextTooShort) {
				t.Errorf("expected error to be %q, got '%q'", ErrCiphertextTooShort, err)
			}
		})
	}
	t.Run("decrypt fails with nil cipher", func(t *testing.T) {
		encryptor := Encryptor{}
		_, err := encryptor.decrypt(nil, nil)
		if err == nil {
			t.Errorf("expected decryption to fail with nil cipher")
		}
		if !errors.Is(err, ErrNoCipher) {
			t.Errorf("expected error to be %q, got '%q'", ErrNoCipher, err)
		}
	})
}

func getTestAEADCipher(t *testing.T, kind string, key []byte) cipher.AEAD {
	t.Helper()
	switch strings.ToLower(kind) {
	case "aes":
		ac, err := aes.NewCipher(key)
		if err != nil {
			t.Fatalf("Failed to create AES cipher: %s", err)
		}
		gcm, err := cipher.NewGCM(ac)
		if err != nil {
			t.Fatalf("Failed to create GCM: %s", err)
		}
		return gcm
	case "chacha20":
		gcm, err := chacha20poly1305.New(key)
		if err != nil {
			t.Fatalf("Failed to create ChaCha20-Poly1305 cipher: %s", err)
		}
		return gcm
	default:
		t.Fatalf("unsupported cipher kind: %s", kind)
		return nil
	}
}

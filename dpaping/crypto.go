// SPDX-License-Identifier: MIT
//
// Cryptographic primitives used by DPAPI-NG / MS-GKDI.
//
// Ported from dpapi-ng (https://github.com/jborean93/dpapi-ng),
// Copyright (c) 2023 Jordan Borean, Red Hat, MIT License.

package dpaping

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"unicode/utf16"
)

// utf16z encodes s as UTF-16LE with a trailing NUL character.
func utf16z(s string) []byte {
	u := utf16.Encode([]rune(s + "\x00"))
	b := make([]byte, len(u)*2)
	for i, c := range u {
		binary.LittleEndian.PutUint16(b[i*2:], c)
	}
	return b
}

// decodeUTF16 decodes UTF-16LE bytes, dropping a trailing NUL if present.
func decodeUTF16(b []byte) string {
	if len(b)%2 == 1 {
		b = b[:len(b)-1]
	}
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(b[i*2:])
	}
	for len(u) > 0 && u[len(u)-1] == 0 {
		u = u[:len(u)-1]
	}
	return string(utf16.Decode(u))
}

var kdsServiceLabel = utf16z("KDS service")

func hashByName(name string) (func() hash.Hash, error) {
	switch name {
	case "SHA1":
		return sha1.New, nil
	case "SHA256":
		return sha256.New, nil
	case "SHA384":
		return sha512.New384, nil
	case "SHA512":
		return sha512.New, nil
	}
	return nil, fmt.Errorf("unsupported hash algorithm %q", name)
}

// kdf implements the NIST SP800-108 KDF in counter mode with HMAC,
// 32-bit big-endian counter before the fixed data, and fixed data
// Label || 0x00 || Context || [L]_32.
func kdf(h func() hash.Hash, secret, label, context []byte, length int) []byte {
	fixed := make([]byte, 0, len(label)+1+len(context)+4)
	fixed = append(fixed, label...)
	fixed = append(fixed, 0)
	fixed = append(fixed, context...)
	fixed = binary.BigEndian.AppendUint32(fixed, uint32(length*8))

	out := make([]byte, 0, length+64)
	mac := hmac.New(h, secret)
	var ctr [4]byte
	for i := uint32(1); len(out) < length; i++ {
		mac.Reset()
		binary.BigEndian.PutUint32(ctr[:], i)
		mac.Write(ctr[:])
		mac.Write(fixed)
		out = mac.Sum(out)
	}
	return out[:length]
}

// kdfConcat implements the NIST SP800-56A single-step (Concat) KDF with a
// hash function: H(counter || Z || OtherInfo).
func kdfConcat(h func() hash.Hash, sharedSecret, otherInfo []byte, length int) []byte {
	out := make([]byte, 0, length+64)
	var ctr [4]byte
	for i := uint32(1); len(out) < length; i++ {
		hh := h()
		binary.BigEndian.PutUint32(ctr[:], i)
		hh.Write(ctr[:])
		hh.Write(sharedSecret)
		hh.Write(otherInfo)
		out = hh.Sum(out)
	}
	return out[:length]
}

var defaultKeyWrapIV = []byte{0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6}

// aesKeyUnwrap implements RFC 3394 AES key unwrap.
func aesKeyUnwrap(kek, wrapped []byte) ([]byte, error) {
	if len(wrapped)%8 != 0 || len(wrapped) < 24 {
		return nil, errors.New("key unwrap: invalid wrapped key length")
	}
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	n := len(wrapped)/8 - 1
	a := make([]byte, 8)
	copy(a, wrapped[:8])
	r := make([]byte, n*8)
	copy(r, wrapped[8:])

	buf := make([]byte, 16)
	for j := 5; j >= 0; j-- {
		for i := n; i >= 1; i-- {
			t := uint64(n*j + i)
			binary.BigEndian.PutUint64(buf[:8], binary.BigEndian.Uint64(a)^t)
			copy(buf[8:], r[(i-1)*8:i*8])
			block.Decrypt(buf, buf)
			copy(a, buf[:8])
			copy(r[(i-1)*8:i*8], buf[8:])
		}
	}
	if subtle.ConstantTimeCompare(a, defaultKeyWrapIV) != 1 {
		return nil, errors.New("key unwrap: integrity check failed (wrong key)")
	}
	return r, nil
}

// aesGCMDecrypt decrypts ciphertext||tag with AES-GCM.
func aesGCMDecrypt(key, nonce, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCMWithNonceSize(block, len(nonce))
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// DecodeUTF16 decodes UTF-16LE bytes into a string, dropping trailing NULs.
func DecodeUTF16(b []byte) string { return decodeUTF16(b) }

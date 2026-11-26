// SPDX-License-Identifier: MIT
//
// MS-GKDI group key handling and DPAPI-NG KEK derivation.
//
// Ported from dpapi-ng (https://github.com/jborean93/dpapi-ng),
// Copyright (c) 2023 Jordan Borean, Red Hat, MIT License.

package dpaping

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"math/big"
)

// GroupKey is an MS-GKDI Group Key Envelope (MS-GKDI 2.2.4) as returned by GetKey.
type GroupKey struct {
	Version          uint32
	Flags            uint32
	L0, L1, L2       int32
	RootKeyID        GUID
	KDFAlgorithm     string
	KDFParameters    []byte
	SecretAlgorithm  string
	SecretParameters []byte
	PrivateKeyLength uint32
	PublicKeyLength  uint32
	Domain, Forest   string
	L1Key, L2Key     []byte
}

// IsPublicKey is set when the caller is only allowed to encrypt: the DC
// returned a public key instead of seed keys, so decryption is not possible.
func (g *GroupKey) IsPublicKey() bool { return g.Flags&1 != 0 }

// ParseGroupKey parses a Group Key Envelope.
func ParseGroupKey(b []byte) (*GroupKey, error) {
	if len(b) < 80 || !bytes.Equal(b[4:8], keyIdentifierMagic) {
		return nil, errors.New("gkdi: invalid group key envelope")
	}
	u32 := func(o int) uint32 { return binary.LittleEndian.Uint32(b[o:]) }
	g := &GroupKey{
		Version:          u32(0),
		Flags:            u32(8),
		L0:               int32(u32(12)),
		L1:               int32(u32(16)),
		L2:               int32(u32(20)),
		PrivateKeyLength: u32(56),
		PublicKeyLength:  u32(60),
	}
	copy(g.RootKeyID[:], b[24:40])
	lens := []uint32{u32(40), u32(44), u32(48), u32(52), u32(72), u32(76), u32(64), u32(68)}
	rest := b[80:]
	fields := make([][]byte, len(lens))
	for i, n := range lens {
		if uint64(n) > uint64(len(rest)) {
			return nil, errors.New("gkdi: truncated group key envelope")
		}
		fields[i], rest = rest[:n], rest[n:]
	}
	g.KDFAlgorithm = decodeUTF16(fields[0])
	g.KDFParameters = fields[1]
	g.SecretAlgorithm = decodeUTF16(fields[2])
	g.SecretParameters = fields[3]
	g.Domain = decodeUTF16(fields[4])
	g.Forest = decodeUTF16(fields[5])
	g.L1Key = fields[6]
	g.L2Key = fields[7]
	return g, nil
}

func (g *GroupKey) hash() (func() hash.Hash, error) {
	if g.KDFAlgorithm != "SP800_108_CTR_HMAC" {
		return nil, fmt.Errorf("gkdi: unsupported KDF algorithm %q", g.KDFAlgorithm)
	}
	// KDF parameters (MS-GKDI 2.2.1): 0x00000000, 0x00000001, len, 0x00000000, UTF-16 hash name.
	p := g.KDFParameters
	if len(p) < 16 || binary.LittleEndian.Uint32(p[4:]) != 1 {
		return nil, errors.New("gkdi: invalid KDF parameters")
	}
	n := int(binary.LittleEndian.Uint32(p[8:]))
	if 16+n > len(p) {
		return nil, errors.New("gkdi: invalid KDF parameters")
	}
	return hashByName(decodeUTF16(p[16 : 16+n]))
}

func kdfContext(root GUID, l0, l1, l2 int32) []byte {
	b := make([]byte, 0, 28)
	b = append(b, root[:]...)
	b = binary.LittleEndian.AppendUint32(b, uint32(l0))
	b = binary.LittleEndian.AppendUint32(b, uint32(l1))
	b = binary.LittleEndian.AppendUint32(b, uint32(l2))
	return b
}

// covers reports whether this group key can derive the key (l1, l2) under the same L0.
func (g *GroupKey) covers(l1, l2 int32) bool {
	return g.L1 > l1 || (g.L1 == l1 && g.L2 >= l2)
}

// l2Key derives the L2 seed key for (reqL1, reqL2) by walking down from the
// indices held in the envelope (MS-GKDI 3.1.4.1.2).
func (g *GroupKey) l2Key(h func() hash.Hash, reqL1, reqL2 int32) []byte {
	l1, l2 := g.L1, g.L2
	l1Key, l2Key := g.L1Key, g.L2Key
	reseed := l2 == 31 || l1 != reqL1

	// If L2 != 31 the L1Key field holds the L1 key for (L0, L1-1).
	if l2 != 31 && l1 != reqL1 {
		l1--
	}
	for l1 != reqL1 {
		reseed = true
		l1--
		l1Key = kdf(h, l1Key, kdsServiceLabel, kdfContext(g.RootKeyID, g.L0, l1, -1), 64)
	}
	if reseed {
		l2 = 31
		l2Key = kdf(h, l1Key, kdsServiceLabel, kdfContext(g.RootKeyID, g.L0, l1, l2), 64)
	}
	for l2 != reqL2 {
		l2--
		l2Key = kdf(h, l2Key, kdsServiceLabel, kdfContext(g.RootKeyID, g.L0, l1, l2), 64)
	}
	return l2Key
}

// KEK derives the key-encryption key for the blob's key identifier.
func (g *GroupKey) KEK(id *KeyIdentifier) ([]byte, error) {
	if g.IsPublicKey() {
		return nil, errors.New("not authorized to decrypt: the DC only returned a public key (account is not in the LAPS encryption principal group)")
	}
	if g.RootKeyID != id.RootKeyID || g.L0 != id.L0 {
		return nil, errors.New("gkdi: group key does not match the blob's key identifier")
	}
	if !g.covers(id.L1, id.L2) {
		return nil, errors.New("gkdi: group key is older than the blob's key identifier")
	}
	h, err := g.hash()
	if err != nil {
		return nil, err
	}
	l2 := g.l2Key(h, id.L1, id.L2)
	if !id.IsPublicKey() {
		return kdf(h, l2, kdsServiceLabel, id.KeyInfo, 32), nil
	}
	privLen := int(g.PrivateKeyLength+7) / 8
	priv := kdf(h, l2, kdsServiceLabel, utf16z(g.SecretAlgorithm), privLen)
	return kekFromPublicKey(h, g.SecretAlgorithm, priv, id.KeyInfo)
}

func kekFromPublicKey(h func() hash.Hash, alg string, priv, pub []byte) ([]byte, error) {
	var shared []byte
	var secretHash func() hash.Hash
	switch alg {
	case "DH":
		// FFC DH public key (MS-GKDI 2.2.3.1): "DHPB", keyLen, p, g, y (big-endian).
		if len(pub) < 8 || string(pub[:4]) != "DHPB" {
			return nil, errors.New("gkdi: invalid DH public key")
		}
		n := int(binary.LittleEndian.Uint32(pub[4:]))
		if len(pub) < 8+3*n {
			return nil, errors.New("gkdi: truncated DH public key")
		}
		p := new(big.Int).SetBytes(pub[8 : 8+n])
		y := new(big.Int).SetBytes(pub[8+2*n : 8+3*n])
		s := new(big.Int).Exp(y, new(big.Int).SetBytes(priv), p)
		shared = s.FillBytes(make([]byte, n))
		secretHash = sha256.New
	case "ECDH_P256", "ECDH_P384", "ECDH_P521":
		// ECDH public key (MS-GKDI 2.2.3.2): "ECK1|3|5", keyLen, X, Y (big-endian).
		if len(pub) < 8 {
			return nil, errors.New("gkdi: invalid ECDH public key")
		}
		var curve ecdh.Curve
		switch string(pub[:4]) {
		case "ECK1":
			curve, secretHash = ecdh.P256(), sha256.New
		case "ECK3":
			curve, secretHash = ecdh.P384(), sha512.New384
		case "ECK5":
			curve, secretHash = ecdh.P521(), sha512.New
		default:
			return nil, errors.New("gkdi: unknown ECDH curve")
		}
		n := int(binary.LittleEndian.Uint32(pub[4:]))
		if len(pub) < 8+2*n {
			return nil, errors.New("gkdi: truncated ECDH public key")
		}
		point := append([]byte{4}, pub[8:8+2*n]...)
		peer, err := curve.NewPublicKey(point)
		if err != nil {
			return nil, fmt.Errorf("gkdi: ECDH public key: %w", err)
		}
		key, err := curve.NewPrivateKey(priv)
		if err != nil {
			return nil, fmt.Errorf("gkdi: ECDH private key: %w", err)
		}
		if shared, err = key.ECDH(peer); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("gkdi: unsupported secret agreement algorithm %q", alg)
	}

	// SP800-56A Concat KDF as done by BCryptDeriveKey(KDF_SP80056A_CONCAT) with
	// AlgorithmID "SHA512", PartyUInfo "KDS public key", PartyVInfo "KDS service".
	pubLabel := utf16z("KDS public key")
	other := append(append(utf16z("SHA512"), pubLabel...), kdsServiceLabel...)
	secret := kdfConcat(secretHash, shared, other, secretHash().Size())
	return kdf(h, secret, kdsServiceLabel, pubLabel, 32), nil
}

// Decrypt decrypts the blob with this group key.
func (g *GroupKey) Decrypt(b *Blob) ([]byte, error) {
	kek, err := g.KEK(b.KeyID)
	if err != nil {
		return nil, err
	}
	if !b.EncCEKAlg.Equal(oidAES256Wrap) {
		return nil, fmt.Errorf("dpapi-ng: unsupported CEK algorithm %v", b.EncCEKAlg)
	}
	cek, err := aesKeyUnwrap(kek, b.EncCEK)
	if err != nil {
		return nil, err
	}
	if !b.EncContentAlg.Equal(oidAES256GCM) {
		return nil, fmt.Errorf("dpapi-ng: unsupported content algorithm %v", b.EncContentAlg)
	}
	return aesGCMDecrypt(cek, b.EncContentIV, b.EncContent)
}

// KeyFetcher retrieves a raw Group Key Envelope, e.g. via MS-GKDI GetKey.
type KeyFetcher interface {
	GetKey(ctx context.Context, targetSD []byte, rootKeyID GUID, l0, l1, l2 int32) ([]byte, error)
}

// DecryptAll decrypts many blobs with as few GetKey calls as possible. Blobs are
// grouped by (root key, protection descriptor, L0); for each group only the key
// with the highest (L1, L2) is requested and every other key in the group is
// derived from it locally. Results and errors are index-aligned with blobs.
func DecryptAll(ctx context.Context, f KeyFetcher, blobs []*Blob) ([][]byte, []error) {
	type groupID struct {
		root GUID
		sd   string
		l0   int32
	}
	type group struct {
		sd      []byte
		l1, l2  int32
		members []int
	}
	out := make([][]byte, len(blobs))
	errs := make([]error, len(blobs))
	groups := map[groupID]*group{}
	var order []groupID

	for i, b := range blobs {
		sd, err := TargetSD(b.ProtectionSID)
		if err != nil {
			errs[i] = err
			continue
		}
		id := groupID{b.KeyID.RootKeyID, string(sd), b.KeyID.L0}
		g := groups[id]
		if g == nil {
			g = &group{sd: sd, l1: b.KeyID.L1, l2: b.KeyID.L2}
			groups[id] = g
			order = append(order, id)
		}
		if b.KeyID.L1 > g.l1 || (b.KeyID.L1 == g.l1 && b.KeyID.L2 > g.l2) {
			g.l1, g.l2 = b.KeyID.L1, b.KeyID.L2
		}
		g.members = append(g.members, i)
	}

	for _, id := range order {
		g := groups[id]
		raw, err := f.GetKey(ctx, g.sd, id.root, id.l0, g.l1, g.l2)
		var gk *GroupKey
		if err == nil {
			gk, err = ParseGroupKey(raw)
		}
		for _, i := range g.members {
			if err != nil {
				errs[i] = err
				continue
			}
			out[i], errs[i] = gk.Decrypt(blobs[i])
		}
	}
	return out, errs
}

// groupKeyFromRootKey derives the L1 seed key for (L0, 31) directly from a KDS
// root key, producing an envelope equivalent to what a DC would return for
// (L0, 31, 31). Used for offline tests with known root keys.
func groupKeyFromRootKey(rootKey []byte, rootID GUID, kdfParams []byte, secretAlg string,
	secretParams []byte, privLen, pubLen uint32, sd []byte, l0 int32) (*GroupKey, error) {
	g := &GroupKey{
		Version: 1, Flags: 2, L0: l0, L1: 31, L2: 31, RootKeyID: rootID,
		KDFAlgorithm: "SP800_108_CTR_HMAC", KDFParameters: kdfParams,
		SecretAlgorithm: secretAlg, SecretParameters: secretParams,
		PrivateKeyLength: privLen, PublicKeyLength: pubLen,
	}
	h, err := g.hash()
	if err != nil {
		return nil, err
	}
	l0Seed := kdf(h, rootKey, kdsServiceLabel, kdfContext(rootID, l0, -1, -1), 64)
	g.L1Key = kdf(h, l0Seed, kdsServiceLabel, append(kdfContext(rootID, l0, 31, -1), sd...), 64)
	return g, nil
}

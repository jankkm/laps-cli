// SPDX-License-Identifier: MIT
//
// Test vectors in testdata/ come from dpapi-ng
// (https://github.com/jborean93/dpapi-ng), Copyright (c) 2023 Jordan Borean,
// Red Hat, MIT License. They were generated on Windows with known KDS root keys.

package dpaping

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func parseGUID(t *testing.T, s string) GUID {
	t.Helper()
	h, err := hex.DecodeString(strings.ReplaceAll(s, "-", ""))
	if err != nil || len(h) != 16 {
		t.Fatalf("bad guid %q", s)
	}
	var g GUID
	binary.LittleEndian.PutUint32(g[0:], binary.BigEndian.Uint32(h[0:]))
	binary.LittleEndian.PutUint16(g[4:], binary.BigEndian.Uint16(h[4:]))
	binary.LittleEndian.PutUint16(g[6:], binary.BigEndian.Uint16(h[6:]))
	copy(g[8:], h[8:])
	return g
}

type rootKeyVector struct {
	RootKeyId                 string
	KdfParameters             string
	SecretAgreementAlgorithm  string
	SecretAgreementParameters string
	PrivateKeyLength          json.Number
	PublicKeyLength           json.Number
	RootKeyData               string
	Data                      string
	Data1                     string
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// rootKeyFetcher answers GetKey from a known KDS root key, like a DC would.
type rootKeyFetcher struct {
	t     *testing.T
	v     rootKeyVector
	calls int
}

func (f *rootKeyFetcher) GetKey(_ context.Context, sd []byte, root GUID, l0, _, _ int32) ([]byte, error) {
	f.calls++
	priv, _ := f.v.PrivateKeyLength.Int64()
	pub, _ := f.v.PublicKeyLength.Int64()
	g, err := groupKeyFromRootKey(mustHex(f.t, f.v.RootKeyData), root, mustHex(f.t, f.v.KdfParameters),
		f.v.SecretAgreementAlgorithm, mustHex(f.t, f.v.SecretAgreementParameters),
		uint32(priv), uint32(pub), sd, l0)
	if err != nil {
		return nil, err
	}
	return marshalGroupKey(g), nil
}

func marshalGroupKey(g *GroupKey) []byte {
	var b []byte
	u32 := func(v uint32) { b = binary.LittleEndian.AppendUint32(b, v) }
	kdfAlg, secAlg := utf16z(g.KDFAlgorithm), utf16z(g.SecretAlgorithm)
	dom, forest := utf16z(g.Domain), utf16z(g.Forest)
	u32(g.Version)
	b = append(b, keyIdentifierMagic...)
	u32(g.Flags)
	u32(uint32(g.L0))
	u32(uint32(g.L1))
	u32(uint32(g.L2))
	b = append(b, g.RootKeyID[:]...)
	for _, n := range []int{len(kdfAlg), len(g.KDFParameters), len(secAlg), len(g.SecretParameters)} {
		u32(uint32(n))
	}
	u32(g.PrivateKeyLength)
	u32(g.PublicKeyLength)
	for _, n := range []int{len(g.L1Key), len(g.L2Key), len(dom), len(forest)} {
		u32(uint32(n))
	}
	for _, f := range [][]byte{kdfAlg, g.KDFParameters, secAlg, g.SecretParameters, dom, forest, g.L1Key, g.L2Key} {
		b = append(b, f...)
	}
	return b
}

func TestDecryptWindowsVectors(t *testing.T) {
	files, _ := filepath.Glob("testdata/kdf_*.json")
	if len(files) == 0 {
		t.Fatal("no test vectors")
	}
	for _, file := range files {
		t.Run(filepath.Base(file), func(t *testing.T) {
			raw, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			var v rootKeyVector
			if err := json.Unmarshal(raw, &v); err != nil {
				t.Fatal(err)
			}
			var blobs []*Blob
			for _, d := range []string{v.Data, v.Data1} {
				if d == "" {
					continue
				}
				b, err := ParseBlob(mustHex(t, d))
				if err != nil {
					t.Fatalf("parse: %v", err)
				}
				if b.KeyID.RootKeyID != parseGUID(t, v.RootKeyId) {
					t.Fatalf("root key id mismatch: %s", b.KeyID.RootKeyID)
				}
				blobs = append(blobs, b)
			}
			f := &rootKeyFetcher{t: t, v: v}
			out, errs := DecryptAll(context.Background(), f, blobs)
			for i := range blobs {
				if errs[i] != nil {
					t.Fatalf("blob %d: %v", i, errs[i])
				}
				if !bytes.Equal(out[i], []byte{0}) {
					t.Fatalf("blob %d: got %x, want 00", i, out[i])
				}
			}
		})
	}
}

func TestParseFixtures(t *testing.T) {
	raw, _ := os.ReadFile("testdata/dpapi_ng_blob")
	b, err := ParseBlob(raw)
	if err != nil {
		t.Fatal(err)
	}
	k := b.KeyID
	if k.Flags != 3 || !k.IsPublicKey() || k.L0 != 361 || k.L1 != 16 || k.L2 != 3 ||
		k.RootKeyID != parseGUID(t, "d778c271-9025-9a82-f6dc-b8960b8ad8c5") ||
		k.Domain != "domain.test" || k.Forest != "domain.test" {
		t.Fatalf("unexpected key identifier: %+v", k)
	}
	if b.ProtectionSID != "S-1-5-21-3337337973-3297078028-437386066-512" {
		t.Fatalf("unexpected SID %q", b.ProtectionSID)
	}

	raw, _ = os.ReadFile("testdata/group_key_envelope")
	g, err := ParseGroupKey(raw)
	if err != nil {
		t.Fatal(err)
	}
	if g.Flags != 2 || g.L0 != 361 || g.L1 != 17 || g.L2 != 8 || g.SecretAlgorithm != "DH" ||
		g.PrivateKeyLength != 512 || g.Domain != "domain.test" || len(g.L1Key) != 64 || len(g.L2Key) != 64 ||
		g.L1Key[0] != 0x9c || g.L2Key[0] != 0x1b {
		t.Fatalf("unexpected group key: %+v", g)
	}
	if !bytes.Equal(marshalGroupKey(g), raw) {
		t.Fatal("group key round-trip mismatch")
	}
}

// The envelope fixture (L1=17, L2=8) is newer than the blob fixture's key
// (L1=16, L2=3) under the same root key and L0, which exercises the
// "walk down from a newer L1" derivation path.
func TestDecryptWithDCEnvelope(t *testing.T) {
	rawBlob, _ := os.ReadFile("testdata/dpapi_ng_blob")
	rawGK, _ := os.ReadFile("testdata/group_key_envelope")
	b, err := ParseBlob(rawBlob)
	if err != nil {
		t.Fatal(err)
	}
	g, err := ParseGroupKey(rawGK)
	if err != nil {
		t.Fatal(err)
	}
	pt, err := g.Decrypt(b)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"n":"Administrator","t":"1d9737aa6ba2536","p":"Z}-FQ5ZjuB+4Yg"}`
	if got := decodeUTF16(pt); got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestTargetSD(t *testing.T) {
	// Layout produced by Windows for SID=S-1-5-21-...-512 (see dpapi-ng seed_key.json).
	want := "0100048054000000600000000000000014000000020040000200000000002400030000000105000000000005150000001A084482EEE8B0C8E6E8BD524F0400000000140002000000010100000000000100000000010100000000000512000000010100000000000512000000"
	sd, err := TargetSD("S-1-5-21-2185496602-3367037166-1388177638-1103")
	if err != nil {
		t.Fatal(err)
	}
	got := strings.ToUpper(hex.EncodeToString(sd))
	if got != want {
		t.Fatalf("SD mismatch\n got %s\nwant %s", got, want)
	}
}

func TestKeyUnwrapRFC3394(t *testing.T) {
	// RFC 3394 section 4.6: 256-bit KEK, 256-bit key data.
	kek := mustHex(t, "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")
	wrapped := mustHex(t, "28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21")
	want := mustHex(t, "00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F")
	got, err := aesKeyUnwrap(kek, wrapped)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("unwrap: %x, %v", got, err)
	}
	wrapped[0] ^= 1
	if _, err := aesKeyUnwrap(kek, wrapped); err == nil {
		t.Fatal("expected integrity failure")
	}
}

func TestDecryptAllBatchesGetKey(t *testing.T) {
	raw, _ := os.ReadFile("testdata/kdf_sha512_ecdh_p384.json")
	var v rootKeyVector
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	var blobs []*Blob
	for i := 0; i < 5; i++ {
		b, err := ParseBlob(mustHex(t, v.Data))
		if err != nil {
			t.Fatal(err)
		}
		blobs = append(blobs, b)
	}
	f := &rootKeyFetcher{t: t, v: v}
	_, errs := DecryptAll(context.Background(), f, blobs)
	for _, err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if f.calls != 1 {
		t.Fatalf("expected 1 GetKey call for 5 blobs, got %d", f.calls)
	}
}

// SPDX-License-Identifier: MIT
//
// DPAPI-NG blob parsing (CMS EnvelopedData with a KEKRecipientInfo).
//
// Ported from dpapi-ng (https://github.com/jborean93/dpapi-ng),
// Copyright (c) 2023 Jordan Borean, Red Hat, MIT License.

package dpaping

import (
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

var (
	oidEnvelopedData       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 3}
	oidMicrosoftSoftware   = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 74, 1}
	oidProtectionDescSID   = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 74, 1, 1}
	oidAES256Wrap          = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 45}
	oidAES256GCM           = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 46}
	keyIdentifierMagic     = []byte{0x4B, 0x44, 0x53, 0x4B} // "KDSK"
	errMalformed           = errors.New("dpapi-ng: malformed blob")
	tagKEKRecipientInfo    = cbasn1.Tag(2).ContextSpecific().Constructed()
	tagContentInfoExplicit = cbasn1.Tag(0).ContextSpecific().Constructed()
	tagEncryptedContent    = cbasn1.Tag(0).ContextSpecific()
)

// GUID is a Windows GUID in its 16-byte mixed-endian wire format.
type GUID [16]byte

func (g GUID) String() string {
	return fmt.Sprintf("%08x-%04x-%04x-%x-%x",
		binary.LittleEndian.Uint32(g[0:4]),
		binary.LittleEndian.Uint16(g[4:6]),
		binary.LittleEndian.Uint16(g[6:8]),
		g[8:10], g[10:16])
}

// KeyIdentifier is the MS-GKDI key identifier embedded in the blob.
type KeyIdentifier struct {
	Version   uint32
	Flags     uint32
	L0, L1    int32
	L2        int32
	RootKeyID GUID
	KeyInfo   []byte
	Domain    string
	Forest    string
}

// IsPublicKey reports whether KeyInfo holds a public key (DH/ECDH) rather than a nonce.
func (k *KeyIdentifier) IsPublicKey() bool { return k.Flags&1 != 0 }

func parseKeyIdentifier(b []byte) (*KeyIdentifier, error) {
	if len(b) < 52 || string(b[4:8]) != string(keyIdentifierMagic) {
		return nil, errors.New("dpapi-ng: invalid key identifier")
	}
	k := &KeyIdentifier{
		Version: binary.LittleEndian.Uint32(b[0:]),
		Flags:   binary.LittleEndian.Uint32(b[8:]),
		L0:      int32(binary.LittleEndian.Uint32(b[12:])),
		L1:      int32(binary.LittleEndian.Uint32(b[16:])),
		L2:      int32(binary.LittleEndian.Uint32(b[20:])),
	}
	copy(k.RootKeyID[:], b[24:40])
	infoLen := int(binary.LittleEndian.Uint32(b[40:]))
	domLen := int(binary.LittleEndian.Uint32(b[44:]))
	forLen := int(binary.LittleEndian.Uint32(b[48:]))
	rest := b[52:]
	if infoLen < 0 || domLen < 0 || forLen < 0 || len(rest) < infoLen+domLen+forLen {
		return nil, errors.New("dpapi-ng: truncated key identifier")
	}
	k.KeyInfo = rest[:infoLen]
	k.Domain = decodeUTF16(rest[infoLen : infoLen+domLen])
	k.Forest = decodeUTF16(rest[infoLen+domLen : infoLen+domLen+forLen])
	return k, nil
}

// Blob is a parsed DPAPI-NG blob.
type Blob struct {
	KeyID         *KeyIdentifier
	ProtectionSID string // protection descriptor "SID=<value>"
	EncCEK        []byte
	EncCEKAlg     asn1.ObjectIdentifier
	EncContent    []byte
	EncContentAlg asn1.ObjectIdentifier
	EncContentIV  []byte
}

// ParseLAPSEncryptedPassword parses the msLAPS-EncryptedPassword attribute:
// a 16-byte header (8-byte timestamp, 4-byte blob length, 4-byte flags)
// followed by a DPAPI-NG blob.
func ParseLAPSEncryptedPassword(attr []byte) (*Blob, error) {
	if len(attr) < 16 {
		return nil, errors.New("msLAPS-EncryptedPassword: too short")
	}
	n := int(binary.LittleEndian.Uint32(attr[8:12]))
	data := attr[16:]
	if n > 0 && n <= len(data) {
		data = data[:n]
	}
	return ParseBlob(data)
}

// ParseBlob parses a DPAPI-NG blob. The encrypted content is either inside the
// EnvelopedData or appended right after the ContentInfo (LAPS style).
func ParseBlob(data []byte) (*Blob, error) {
	in := cryptobyte.String(data)
	var contentInfo cryptobyte.String
	if !in.ReadASN1(&contentInfo, cbasn1.SEQUENCE) {
		return nil, errMalformed
	}
	trailing := []byte(in)

	var ct asn1.ObjectIdentifier
	var explicit, env cryptobyte.String
	if !contentInfo.ReadASN1ObjectIdentifier(&ct) || !ct.Equal(oidEnvelopedData) ||
		!contentInfo.ReadASN1(&explicit, tagContentInfoExplicit) ||
		!explicit.ReadASN1(&env, cbasn1.SEQUENCE) {
		return nil, errors.New("dpapi-ng: not a CMS EnvelopedData")
	}

	var version int
	if !env.ReadASN1Integer(&version) || version != 2 {
		return nil, errors.New("dpapi-ng: unsupported EnvelopedData version")
	}
	// Skip optional originatorInfo [0].
	env.SkipOptionalASN1(cbasn1.Tag(0).ContextSpecific().Constructed())

	var recipients cryptobyte.String
	if !env.ReadASN1(&recipients, cbasn1.SET) {
		return nil, errMalformed
	}
	var kekri cryptobyte.String
	if !recipients.ReadASN1(&kekri, tagKEKRecipientInfo) || !recipients.Empty() {
		return nil, errors.New("dpapi-ng: expected exactly one KEKRecipientInfo")
	}

	b := &Blob{}
	var kekVersion int
	var kekid, keyIDBytes, other cryptobyte.String
	if !kekri.ReadASN1Integer(&kekVersion) || kekVersion != 4 ||
		!kekri.ReadASN1(&kekid, cbasn1.SEQUENCE) ||
		!kekid.ReadASN1(&keyIDBytes, cbasn1.OCTET_STRING) {
		return nil, errMalformed
	}
	kekid.SkipOptionalASN1(cbasn1.GeneralizedTime)
	if !kekid.ReadASN1(&other, cbasn1.SEQUENCE) {
		return nil, errors.New("dpapi-ng: missing protection descriptor")
	}
	var attrID asn1.ObjectIdentifier
	if !other.ReadASN1ObjectIdentifier(&attrID) || !attrID.Equal(oidMicrosoftSoftware) {
		return nil, errors.New("dpapi-ng: unexpected KEK identifier attribute")
	}
	sid, err := parseProtectionDescriptor(other)
	if err != nil {
		return nil, err
	}
	b.ProtectionSID = sid

	if b.KeyID, err = parseKeyIdentifier(keyIDBytes); err != nil {
		return nil, err
	}

	var kekAlg cryptobyte.String
	var encKey []byte
	if !kekri.ReadASN1(&kekAlg, cbasn1.SEQUENCE) ||
		!kekAlg.ReadASN1ObjectIdentifier(&b.EncCEKAlg) ||
		!kekri.ReadASN1Bytes(&encKey, cbasn1.OCTET_STRING) {
		return nil, errMalformed
	}
	b.EncCEK = encKey

	var eci, contAlg cryptobyte.String
	var eciType asn1.ObjectIdentifier
	if !env.ReadASN1(&eci, cbasn1.SEQUENCE) ||
		!eci.ReadASN1ObjectIdentifier(&eciType) ||
		!eci.ReadASN1(&contAlg, cbasn1.SEQUENCE) ||
		!contAlg.ReadASN1ObjectIdentifier(&b.EncContentAlg) {
		return nil, errMalformed
	}
	if b.EncContentAlg.Equal(oidAES256GCM) {
		// GCMParameters ::= SEQUENCE { aes-nonce OCTET STRING, aes-ICVlen INTEGER DEFAULT 12 }
		var params cryptobyte.String
		var iv []byte
		if !contAlg.ReadASN1(&params, cbasn1.SEQUENCE) || !params.ReadASN1Bytes(&iv, cbasn1.OCTET_STRING) {
			return nil, errors.New("dpapi-ng: missing AES-GCM parameters")
		}
		b.EncContentIV = iv
	}
	var content []byte
	if eci.PeekASN1Tag(tagEncryptedContent) {
		if !eci.ReadASN1Bytes(&content, tagEncryptedContent) {
			return nil, errMalformed
		}
	}
	if len(content) == 0 {
		content = trailing
	}
	b.EncContent = content
	return b, nil
}

// parseProtectionDescriptor parses the key attribute holding the protection
// descriptor. Only "SID=..." descriptors are supported (what LAPS uses).
//
//	SEQUENCE { OID, SEQUENCE { SEQUENCE { SEQUENCE { UTF8String type, UTF8String value } } } }
func parseProtectionDescriptor(s cryptobyte.String) (string, error) {
	var pd, l1, l2, l3 cryptobyte.String
	var typ asn1.ObjectIdentifier
	var name, value []byte
	if !s.ReadASN1(&pd, cbasn1.SEQUENCE) ||
		!pd.ReadASN1ObjectIdentifier(&typ) ||
		!pd.ReadASN1(&l1, cbasn1.SEQUENCE) ||
		!l1.ReadASN1(&l2, cbasn1.SEQUENCE) ||
		!l2.ReadASN1(&l3, cbasn1.SEQUENCE) ||
		!l3.ReadASN1Bytes(&name, cbasn1.UTF8String) ||
		!l3.ReadASN1Bytes(&value, cbasn1.UTF8String) {
		return "", errors.New("dpapi-ng: malformed protection descriptor")
	}
	if !typ.Equal(oidProtectionDescSID) || string(name) != "SID" {
		return "", fmt.Errorf("dpapi-ng: unsupported protection descriptor %v %q", typ, name)
	}
	if !l1.Empty() || !l2.Empty() || !l3.Empty() {
		return "", errors.New("dpapi-ng: compound protection descriptors are not supported")
	}
	return string(value), nil
}

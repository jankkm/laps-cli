// SPDX-License-Identifier: MIT

package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jankkm/laps-cli/dpaping"
)

// fixtureFetcher returns the DC group key envelope fixture for any request.
type fixtureFetcher struct{ calls int }

func (f *fixtureFetcher) GetKey(context.Context, []byte, dpaping.GUID, int32, int32, int32) ([]byte, error) {
	f.calls++
	return os.ReadFile("dpaping/testdata/group_key_envelope")
}

func lapsAttr(t *testing.T) []byte {
	blob, err := os.ReadFile("dpaping/testdata/dpapi_ng_blob")
	if err != nil {
		t.Fatal(err)
	}
	hdr := make([]byte, 16)
	binary.LittleEndian.PutUint32(hdr[8:], uint32(len(blob)))
	return append(hdr, blob...)
}

func testEntries(t *testing.T) []*computer {
	return []*computer{
		{CN: "ENC01", SAM: "ENC01$", DNSHostName: "enc01.corp.test", Encrypted: lapsAttr(t), Expiry: "134089920000000000"},
		{CN: "ENC02", SAM: "ENC02$", Encrypted: lapsAttr(t)},
		{CN: "CLR01", SAM: "CLR01$", Cleartext: `{"n":"LocalAdmin","t":"1d9737aa6ba2536","p":"cl3ar!"}`},
		{CN: "OLD01", SAM: "OLD01$", Legacy: "legacyPw", LegacyExpiry: "134089920000000000"},
		{CN: "NOPE01", SAM: "NOPE01$"},
	}
}

func TestResolveMixed(t *testing.T) {
	f := &fixtureFetcher{}
	names := []string{"enc01", "CLR01", "missing", "OLD01", "nope01", "ENC01.corp.test", "ENC02"}
	res := resolve(context.Background(), names, testEntries(t), "auto", f)

	want := []struct {
		computer, password, source string
		err                        bool
	}{
		{"ENC01", "Z}-FQ5ZjuB+4Yg", sourceEncrypted, false},
		{"CLR01", "cl3ar!", sourceCleartext, false},
		{"missing", "", "", true},
		{"OLD01", "legacyPw", sourceLegacy, false},
		{"NOPE01", "", "", true},
		{"ENC01", "Z}-FQ5ZjuB+4Yg", sourceEncrypted, false},
		{"ENC02", "Z}-FQ5ZjuB+4Yg", sourceEncrypted, false},
	}
	for i, w := range want {
		r := res[i]
		if r.Computer != w.computer || r.Password != w.password || r.Source != w.source || (r.Error != "") != w.err {
			t.Errorf("%d: got %+v, want %+v", i, r, w)
		}
	}
	if res[0].Account != "Administrator" || res[0].Expiry == nil || res[0].Updated == nil {
		t.Errorf("missing metadata: %+v", res[0])
	}
	if res[1].Account != "LocalAdmin" {
		t.Errorf("cleartext account: %+v", res[1])
	}
	if f.calls != 1 {
		t.Errorf("3 encrypted lookups should need 1 GetKey call, got %d", f.calls)
	}
}

func TestResolveForcedSource(t *testing.T) {
	res := resolve(context.Background(), []string{"ENC01", "OLD01"}, testEntries(t), "legacy", &fixtureFetcher{})
	if res[0].Error == "" || res[1].Password != "legacyPw" {
		t.Fatalf("unexpected: %+v", res)
	}
}

func TestPlainOutputAligned(t *testing.T) {
	res := []Result{{Computer: "A", Password: "pa"}, {Computer: "B", Error: "boom"}, {Computer: "C", Password: "pc"}}
	var out, errOut bytes.Buffer
	writePlain(&out, &errOut, res)
	if out.String() != "pa\n\npc\n" {
		t.Fatalf("stdout %q", out.String())
	}
	if errOut.String() != "B: boom\n" {
		t.Fatalf("stderr %q", errOut.String())
	}
}

func TestJSONOutput(t *testing.T) {
	res := resolve(context.Background(), []string{"ENC01", "missing"}, testEntries(t), "auto", &fixtureFetcher{})

	var buf bytes.Buffer
	if err := writeJSON(&buf, res); err != nil {
		t.Fatal(err)
	}
	var j []Result
	if err := json.Unmarshal(buf.Bytes(), &j); err != nil || len(j) != 2 || j[0].Password != "Z}-FQ5ZjuB+4Yg" || j[1].Error == "" {
		t.Fatalf("json: %s", buf.String())
	}
}

func TestParseArgsAndNames(t *testing.T) {
	o, pos, err := parseArgs([]string{"PC1", "-d", "corp.test", "PC2,PC3", "--json", "-u", "admin", "-"})
	if err != nil {
		t.Fatal(err)
	}
	if o.domain != "corp.test" || o.user != "admin" || !o.jsonOut {
		t.Fatalf("options: %+v", o)
	}
	names, err := collectNames(pos, bufio.NewReader(strings.NewReader("PC4\n\nPC5 PC6\n")))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(names, ","); got != "PC1,PC2,PC3,PC4,PC5,PC6" {
		t.Fatalf("names: %s", got)
	}
	if _, _, err := parseArgs([]string{"--source", "bogus"}); err == nil {
		t.Fatal("expected error for invalid source")
	}
}

func TestPasswordStdinThenNames(t *testing.T) {
	o, pos, _ := parseArgs([]string{"--password-stdin", "-"})
	in := bufio.NewReader(strings.NewReader("s3cret\nPC1\nPC2\n"))
	pw, err := readPassword(o, in)
	if err != nil || pw != "s3cret" {
		t.Fatalf("password %q %v", pw, err)
	}
	names, _ := collectNames(pos, in)
	if strings.Join(names, ",") != "PC1,PC2" {
		t.Fatalf("names %v", names)
	}
}

func TestDomainToBaseDN(t *testing.T) {
	if got := domainToBaseDN("corp.example.com"); got != "DC=corp,DC=example,DC=com" {
		t.Fatal(got)
	}
}

func TestNameFilterEscapes(t *testing.T) {
	if got := nameFilter("a*b"); got != `(sAMAccountName=a\2ab$)(cn=a\2ab)` {
		t.Fatal(got)
	}
	if got := nameFilter("pc.corp.test"); got != "(dNSHostName=pc.corp.test)" {
		t.Fatal(got)
	}
}

func TestFileTime(t *testing.T) {
	if fileTime(0) != nil || fileTime(0x7FFFFFFFFFFFFFFF) != nil {
		t.Fatal("expected nil for unset/never")
	}
	if got := fileTime(116444736000000000 + 10_000_000).Unix(); got != 1 {
		t.Fatalf("got %d", got)
	}
}

func TestLoadCAPool(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test Root"},
		NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	pemFile, derFile, badFile := dir+"/ca.pem", dir+"/ca.der", dir+"/bad.txt"
	os.WriteFile(pemFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	os.WriteFile(derFile, der, 0o600)
	os.WriteFile(badFile, []byte("nope"), 0o600)
	for _, f := range []string{pemFile, derFile} {
		if _, err := loadCAPool(f); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
	}
	if _, err := loadCAPool(badFile); err == nil {
		t.Fatal("expected error for invalid file")
	}
}

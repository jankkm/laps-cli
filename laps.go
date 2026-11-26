// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jankkm/laps-cli/dpaping"
)

const (
	sourceEncrypted = "EncryptedPassword"
	sourceCleartext = "CleartextPassword"
	sourceLegacy    = "Legacy"
)

// Result is one line of output, index-aligned with the requested names.
type Result struct {
	Computer string     `json:"computer"`
	Password string     `json:"password,omitempty"`
	Account  string     `json:"account,omitempty"`
	Expiry   *time.Time `json:"expiry,omitempty"`
	Updated  *time.Time `json:"updated,omitempty"`
	Source   string     `json:"source,omitempty"`
	Error    string     `json:"error,omitempty"`
}

// windowsLAPSPayload is the JSON stored in msLAPS-Password and, after
// decryption, in msLAPS-EncryptedPassword.
type windowsLAPSPayload struct {
	Account  string `json:"n"`
	Updated  string `json:"t"` // FILETIME, hex
	Password string `json:"p"`
}

// fileTime converts a Windows FILETIME (100ns ticks since 1601) to time.
func fileTime(v uint64) *time.Time {
	// 0 and very large values (e.g. 0x7FFFFFFFFFFFFFFF) mean "not set" / "never".
	if v == 0 || v >= 1<<62 {
		return nil
	}
	const epochDiff = 116444736000000000
	t := time.Unix(0, 0).Add(time.Duration(int64(v)-epochDiff) * 100).UTC()
	return &t
}

func parseFileTime(s string, base int) *time.Time {
	v, err := strconv.ParseUint(strings.TrimSpace(s), base, 64)
	if err != nil {
		return nil
	}
	return fileTime(v)
}

func applyWindowsPayload(r *Result, raw string) error {
	var p windowsLAPSPayload
	if err := json.Unmarshal([]byte(raw), &p); err != nil {
		return fmt.Errorf("invalid Windows LAPS payload: %w", err)
	}
	r.Password, r.Account, r.Updated = p.Password, p.Account, parseFileTime(p.Updated, 16)
	return nil
}

var errNoPassword = errors.New("no LAPS password found (not managed by LAPS, or no permission to read it)")

// resolve picks the password source for every requested computer and decrypts
// all encrypted passwords in one batch.
func resolve(ctx context.Context, names []string, entries []*computer, source string, keys dpaping.KeyFetcher) []Result {
	results := make([]Result, len(names))
	var blobs []*dpaping.Blob
	var blobOwners []int

	for i, name := range names {
		r := &results[i]
		r.Computer = name
		c := matchComputer(entries, name)
		if c == nil {
			r.Error = "computer not found"
			continue
		}
		r.Computer = strings.TrimSuffix(c.SAM, "$")
		if r.Computer == "" {
			r.Computer = c.CN
		}

		var err error
		switch {
		case len(c.Encrypted) > 0 && (source == "auto" || source == "encrypted"):
			r.Source = sourceEncrypted
			r.Expiry = parseFileTime(c.Expiry, 10)
			var b *dpaping.Blob
			if b, err = dpaping.ParseLAPSEncryptedPassword(c.Encrypted); err == nil {
				blobs = append(blobs, b)
				blobOwners = append(blobOwners, i)
			}
		case c.Cleartext != "" && (source == "auto" || source == "cleartext"):
			r.Source = sourceCleartext
			r.Expiry = parseFileTime(c.Expiry, 10)
			err = applyWindowsPayload(r, c.Cleartext)
		case c.Legacy != "" && (source == "auto" || source == "legacy"):
			r.Source = sourceLegacy
			r.Password = c.Legacy
			r.Expiry = parseFileTime(c.LegacyExpiry, 10)
		default:
			err = errNoPassword
		}
		if err != nil {
			r.Error = err.Error()
		}
	}

	if len(blobs) > 0 {
		plain, errs := dpaping.DecryptAll(ctx, keys, blobs)
		for j, i := range blobOwners {
			r := &results[i]
			err := errs[j]
			if err == nil {
				err = applyWindowsPayload(r, dpaping.DecodeUTF16(plain[j]))
			}
			if err != nil {
				r.Error = err.Error()
			}
		}
	}
	return results
}

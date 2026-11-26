// SPDX-License-Identifier: MIT
//
// Security descriptor construction for MS-GKDI GetKey.
//
// Ported from dpapi-ng (https://github.com/jborean93/dpapi-ng),
// Copyright (c) 2023 Jordan Borean, Red Hat, MIT License.

package dpaping

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
)

func sidToBytes(sid string) ([]byte, error) {
	parts := strings.Split(sid, "-")
	if len(parts) < 4 || len(parts) > 18 || !strings.EqualFold(parts[0], "S") {
		return nil, fmt.Errorf("invalid SID %q", sid)
	}
	rev, err1 := strconv.ParseUint(parts[1], 10, 8)
	auth, err2 := strconv.ParseUint(parts[2], 10, 48)
	if err1 != nil || err2 != nil {
		return nil, fmt.Errorf("invalid SID %q", sid)
	}
	b := make([]byte, 8, 8+4*(len(parts)-3))
	binary.BigEndian.PutUint64(b, auth)
	b[0] = byte(rev)
	b[1] = byte(len(parts) - 3)
	for _, p := range parts[3:] {
		sub, err := strconv.ParseUint(p, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid SID %q", sid)
		}
		b = binary.LittleEndian.AppendUint32(b, uint32(sub))
	}
	return b, nil
}

func aceBytes(sid string, mask uint32) ([]byte, error) {
	s, err := sidToBytes(sid)
	if err != nil {
		return nil, err
	}
	b := []byte{0, 0} // ACCESS_ALLOWED_ACE_TYPE, no flags
	b = binary.LittleEndian.AppendUint16(b, uint16(8+len(s)))
	b = binary.LittleEndian.AppendUint32(b, mask)
	return append(b, s...), nil
}

// TargetSD builds the self-relative security descriptor that Windows uses
// when requesting the group key for a "SID=<sid>" protection descriptor:
// owner/group SYSTEM, DACL [allow <sid> 0x3, allow Everyone 0x2].
// The byte layout (DACL, owner, group) must match what the DC computes.
func TargetSD(sid string) ([]byte, error) {
	ace1, err := aceBytes(sid, 3)
	if err != nil {
		return nil, err
	}
	ace2, _ := aceBytes("S-1-1-0", 2)
	acl := []byte{2, 0}
	acl = binary.LittleEndian.AppendUint16(acl, uint16(8+len(ace1)+len(ace2)))
	acl = binary.LittleEndian.AppendUint16(acl, 2)
	acl = append(acl, 0, 0)
	acl = append(append(acl, ace1...), ace2...)

	system, _ := sidToBytes("S-1-5-18")
	const hdr = 20
	daclOff := hdr
	ownerOff := daclOff + len(acl)
	groupOff := ownerOff + len(system)
	control := uint16(0x8000 | 0x0004) // self-relative, DACL present

	sd := []byte{1, 0}
	sd = binary.LittleEndian.AppendUint16(sd, control)
	sd = binary.LittleEndian.AppendUint32(sd, uint32(ownerOff))
	sd = binary.LittleEndian.AppendUint32(sd, uint32(groupOff))
	sd = binary.LittleEndian.AppendUint32(sd, 0) // no SACL
	sd = binary.LittleEndian.AppendUint32(sd, uint32(daclOff))
	sd = append(sd, acl...)
	sd = append(sd, system...)
	sd = append(sd, system...)
	return sd, nil
}

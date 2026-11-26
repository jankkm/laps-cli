// SPDX-License-Identifier: MIT

package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

const (
	attrEncrypted    = "msLAPS-EncryptedPassword"
	attrCleartext    = "msLAPS-Password"
	attrExpiry       = "msLAPS-PasswordExpirationTime"
	attrLegacy       = "ms-Mcs-AdmPwd"
	attrLegacyExpiry = "ms-Mcs-AdmPwdExpirationTime"
	namesPerFilter   = 100
	ldapPageSize     = 500
)

type ldapConfig struct {
	Server   string
	BaseDN   string
	BindUser string
	Password string
	StartTLS bool
	Insecure bool
	CAFile   string
	Timeout  time.Duration
}

// loadCAPool returns the system trust store plus the certificates in caFile
// (PEM, one or more certificates, or a single DER certificate).
func loadCAPool(caFile string) (*x509.CertPool, error) {
	data, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("ca-file: %w", err)
	}
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if pool.AppendCertsFromPEM(data) {
		return pool, nil
	}
	cert, err := x509.ParseCertificate(data)
	if err != nil {
		return nil, fmt.Errorf("ca-file %s: no PEM or DER certificate found", caFile)
	}
	pool.AddCert(cert)
	return pool, nil
}

type computer struct {
	CN, SAM, DNSHostName string
	Encrypted            []byte
	Cleartext            string
	Expiry               string
	Legacy               string
	LegacyExpiry         string
}

func domainToBaseDN(domain string) string {
	parts := strings.Split(strings.Trim(domain, "."), ".")
	for i, p := range parts {
		parts[i] = "DC=" + p
	}
	return strings.Join(parts, ",")
}

func connectLDAP(cfg ldapConfig) (*ldap.Conn, error) {
	host := cfg.Server
	tlsConf := &tls.Config{ServerName: host, InsecureSkipVerify: cfg.Insecure}
	if cfg.CAFile != "" {
		pool, err := loadCAPool(cfg.CAFile)
		if err != nil {
			return nil, err
		}
		tlsConf.RootCAs = pool
	}
	dialer := &net.Dialer{Timeout: cfg.Timeout}

	var conn *ldap.Conn
	var err error
	if cfg.StartTLS {
		conn, err = ldap.DialURL("ldap://"+net.JoinHostPort(host, "389"), ldap.DialWithDialer(dialer))
		if err == nil {
			if err = conn.StartTLS(tlsConf); err != nil {
				conn.Close()
			}
		}
	} else {
		conn, err = ldap.DialURL("ldaps://"+net.JoinHostPort(host, "636"),
			ldap.DialWithDialer(dialer), ldap.DialWithTLSConfig(tlsConf))
	}
	if err != nil {
		return nil, fmt.Errorf("ldap connect to %s: %w", host, err)
	}
	conn.SetTimeout(cfg.Timeout)

	if err := conn.Bind(cfg.BindUser, cfg.Password); err != nil {
		conn.Close()
		return nil, fmt.Errorf("ldap bind as %s: %w", cfg.BindUser, err)
	}
	return conn, nil
}

// nameFilter matches a computer by short name (sAMAccountName / cn) or,
// when the name contains a dot, by dNSHostName.
func nameFilter(name string) string {
	e := ldap.EscapeFilter(name)
	if strings.Contains(name, ".") {
		return "(dNSHostName=" + e + ")"
	}
	return "(sAMAccountName=" + e + "$)(cn=" + e + ")"
}

// searchComputers fetches all requested computers with as few LDAP round trips
// as possible (one search per chunk of names).
func searchComputers(conn *ldap.Conn, baseDN string, names []string) ([]*computer, error) {
	var out []*computer
	for start := 0; start < len(names); start += namesPerFilter {
		end := min(start+namesPerFilter, len(names))
		var f strings.Builder
		f.WriteString("(&(objectCategory=computer)(|")
		for _, n := range names[start:end] {
			f.WriteString(nameFilter(n))
		}
		f.WriteString("))")

		req := ldap.NewSearchRequest(baseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
			f.String(),
			[]string{"cn", "sAMAccountName", "dNSHostName", attrEncrypted, attrCleartext, attrExpiry, attrLegacy, attrLegacyExpiry},
			nil)
		res, err := conn.SearchWithPaging(req, ldapPageSize)
		if err != nil {
			return nil, fmt.Errorf("ldap search: %w", err)
		}
		for _, e := range res.Entries {
			out = append(out, &computer{
				CN:           e.GetAttributeValue("cn"),
				SAM:          e.GetAttributeValue("sAMAccountName"),
				DNSHostName:  e.GetAttributeValue("dNSHostName"),
				Encrypted:    e.GetRawAttributeValue(attrEncrypted),
				Cleartext:    e.GetAttributeValue(attrCleartext),
				Expiry:       e.GetAttributeValue(attrExpiry),
				Legacy:       e.GetAttributeValue(attrLegacy),
				LegacyExpiry: e.GetAttributeValue(attrLegacyExpiry),
			})
		}
	}
	return out, nil
}

// matchComputer finds the entry for a requested name (case-insensitive).
func matchComputer(entries []*computer, name string) *computer {
	for _, c := range entries {
		if strings.Contains(name, ".") {
			if strings.EqualFold(c.DNSHostName, name) {
				return c
			}
			continue
		}
		if strings.EqualFold(strings.TrimSuffix(c.SAM, "$"), name) || strings.EqualFold(c.CN, name) {
			return c
		}
	}
	return nil
}

// SPDX-License-Identifier: MIT

// laps-cli retrieves Windows LAPS (encrypted or cleartext) and legacy LAPS
// passwords from Active Directory.
package main

import (
	"bufio"
	"context"
	_ "embed"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/jankkm/laps-cli/dpaping"
)

// VERSION is the single source of truth for the release version.
//
//go:embed VERSION
var versionFile string

var version = strings.TrimSpace(versionFile)

const usageText = `Usage: laps-cli [flags] PC [PC ...]

Retrieves LAPS passwords from Active Directory. Supports Windows LAPS
(encrypted and cleartext) and legacy Microsoft LAPS, auto-detected per computer.

PCs can be given as arguments, comma-separated, or "-" to read names from
stdin (one per line). A name containing a dot is matched against dNSHostName.

Output (default): one password per line, in input order. A computer that
fails gives an empty line, and the error goes to stderr.

Connection:
  -d, --domain DOMAIN     AD domain, e.g. corp.example.com      [$LAPS_DOMAIN]
  -s, --dc HOST           domain controller FQDN (default: domain) [$LAPS_DC]
  -u, --user USER         user, user@domain or DOMAIN\user        [$LAPS_USER]
  -p, --password PASS     password (visible in ps; prefer env)  [$LAPS_PASSWORD]
      --password-stdin    read the password from the first line of stdin
      --base DN           LDAP search base (default: from domain) [$LAPS_BASE_DN]
      --starttls          LDAP+StartTLS on 389 instead of LDAPS 636 [$LAPS_STARTTLS]
      --ca-file FILE      trust this CA (PEM/DER) for LDAPS     [$LAPS_CA_FILE]
      --insecure          skip TLS certificate verification     [$LAPS_INSECURE]
      --timeout DURATION  network timeout (default 10s)

Output:
      --json              JSON array: computer, password, account, expiry, updated, source, error
      --source SOURCE     auto (default), encrypted, cleartext or legacy
      --version           print version and exit

Exit status: 0 all found, 1 some computers failed, 2 usage/connection/auth error.
`

type options struct {
	domain, server, user, password, base, source, caFile string
	passwordStdin, jsonOut                               bool
	insecure, startTLS, showVersion                      bool
	timeout                                              time.Duration
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envBool(key string) bool {
	switch strings.ToLower(os.Getenv(key)) {
	case "1", "true", "yes":
		return true
	}
	return false
}

func parseArgs(args []string) (*options, []string, error) {
	o := &options{}
	fs := flag.NewFlagSet("laps-cli", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), usageText)
	}
	str := func(p *string, short, long, env, def, usage string) {
		def = envOr(env, def)
		if env != "" {
			usage += " [$" + env + "]"
		}
		if short != "" {
			fs.StringVar(p, short, def, usage)
		}
		fs.StringVar(p, long, def, usage)
	}
	str(&o.domain, "d", "domain", "LAPS_DOMAIN", "", "AD domain, e.g. corp.example.com")
	str(&o.server, "s", "dc", "LAPS_DC", "", "domain controller FQDN (default: the domain name)")
	str(&o.user, "u", "user", "LAPS_USER", "", "username (user, user@domain or DOMAIN\\user)")
	str(&o.password, "p", "password", "LAPS_PASSWORD", "", "password (prefer $LAPS_PASSWORD or --password-stdin)")
	str(&o.base, "", "base", "LAPS_BASE_DN", "", "LDAP search base (default: derived from domain)")
	str(&o.caFile, "", "ca-file", "LAPS_CA_FILE", "", "extra trusted CA certificate(s) for LDAPS, PEM or DER")
	str(&o.source, "", "source", "", "auto", "password source: auto, encrypted, cleartext, legacy")
	fs.BoolVar(&o.passwordStdin, "password-stdin", false, "read the password from the first line of stdin")
	fs.BoolVar(&o.jsonOut, "json", false, "output a JSON array")
	fs.BoolVar(&o.insecure, "insecure", envBool("LAPS_INSECURE"), "skip TLS certificate verification [$LAPS_INSECURE]")
	fs.BoolVar(&o.startTLS, "starttls", envBool("LAPS_STARTTLS"), "use LDAP+StartTLS on 389 instead of LDAPS on 636 [$LAPS_STARTTLS]")
	fs.DurationVar(&o.timeout, "timeout", 10*time.Second, "network timeout")
	fs.BoolVar(&o.showVersion, "version", false, "print version and exit")

	// Allow flags and PC names in any order.
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, nil, err
		}
		rest := fs.Args()
		if len(rest) == 0 {
			break
		}
		pos = append(pos, rest[0])
		args = rest[1:]
	}
	switch o.source {
	case "auto", "encrypted", "cleartext", "legacy":
	default:
		return nil, nil, fmt.Errorf("invalid --source %q", o.source)
	}
	return o, pos, nil
}

func collectNames(pos []string, stdin *bufio.Reader) ([]string, error) {
	var names []string
	add := func(s string) {
		for _, n := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' }) {
			names = append(names, n)
		}
	}
	for _, p := range pos {
		if p != "-" {
			add(p)
			continue
		}
		sc := bufio.NewScanner(stdin)
		for sc.Scan() {
			add(sc.Text())
		}
		if err := sc.Err(); err != nil {
			return nil, err
		}
	}
	return names, nil
}

func readPassword(o *options, stdin *bufio.Reader) (string, error) {
	if o.passwordStdin {
		line, err := stdin.ReadString('\n')
		if err != nil && !(errors.Is(err, io.EOF) && line != "") {
			return "", fmt.Errorf("reading password from stdin: %w", err)
		}
		return strings.TrimRight(line, "\r\n"), nil
	}
	if o.password != "" {
		return o.password, nil
	}
	// Prompt on the controlling terminal so stdin/stdout stay free for data.
	ttyIn, ttyOut := "/dev/tty", "/dev/tty"
	if runtime.GOOS == "windows" {
		ttyIn, ttyOut = "CONIN$", "CONOUT$"
	}
	in, err := os.OpenFile(ttyIn, os.O_RDWR, 0)
	if err != nil {
		return "", errors.New("no password given: use $LAPS_PASSWORD, --password-stdin or -p")
	}
	defer in.Close()
	var out io.Writer = os.Stderr
	if f, err := os.OpenFile(ttyOut, os.O_WRONLY, 0); err == nil {
		defer f.Close()
		out = f
	}
	fmt.Fprintf(out, "Password for %s: ", o.user)
	b, err := term.ReadPassword(int(in.Fd()))
	fmt.Fprintln(out)
	return string(b), err
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdinFile io.Reader, stdout, stderr io.Writer) int {
	o, pos, err := parseArgs(args)
	if errors.Is(err, flag.ErrHelp) {
		return 0
	}
	if err != nil {
		fmt.Fprintln(stderr, "laps-cli:", err)
		return 2
	}
	if o.showVersion {
		fmt.Fprintln(stdout, "laps-cli", version)
		return 0
	}

	stdin := bufio.NewReader(stdinFile)
	var password string
	if o.passwordStdin { // password comes first on stdin, before any PC names
		if password, err = readPassword(o, stdin); err != nil {
			fmt.Fprintln(stderr, "laps-cli:", err)
			return 2
		}
	}
	names, err := collectNames(pos, stdin)
	if err == nil && len(names) == 0 {
		err = errors.New("no computer names given (see --help)")
	}
	if err == nil && (o.domain == "" || o.user == "") {
		err = errors.New("--domain and --user are required")
	}
	if err == nil && !o.passwordStdin {
		password, err = readPassword(o, stdin)
	}
	if err != nil {
		fmt.Fprintln(stderr, "laps-cli:", err)
		return 2
	}

	fail := func(err error) int {
		results := make([]Result, len(names))
		for i, n := range names {
			results[i] = Result{Computer: n, Error: err.Error()}
		}
		if o.jsonOut {
			writeJSON(stdout, results)
		}
		fmt.Fprintln(stderr, "laps-cli:", err)
		return 2
	}

	server := o.server
	if server == "" {
		server = o.domain
	}
	bindUser := o.user
	if !strings.ContainsAny(bindUser, "@\\") {
		bindUser += "@" + o.domain
	}
	base := o.base
	if base == "" {
		base = domainToBaseDN(o.domain)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	conn, err := connectLDAP(ldapConfig{
		Server: server, BindUser: bindUser, Password: password,
		StartTLS: o.startTLS, Insecure: o.insecure, CAFile: o.caFile, Timeout: o.timeout,
	})
	if err != nil {
		return fail(err)
	}
	entries, err := searchComputers(conn, base, names)
	conn.Close()
	if err != nil {
		return fail(err)
	}

	rpc := &dpaping.RPCClient{Server: server, Username: bindUser, Password: password, Timeout: o.timeout}
	defer rpc.Close()
	results := resolve(ctx, names, entries, o.source, rpc)

	if o.jsonOut {
		err = writeJSON(stdout, results)
	} else {
		writePlain(stdout, stderr, results)
	}
	if err != nil {
		fmt.Fprintln(stderr, "laps-cli:", err)
		return 2
	}
	for _, r := range results {
		if r.Error != "" {
			return 1
		}
	}
	return 0
}

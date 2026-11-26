# laps-cli

A small, fast command-line tool that reads LAPS passwords from Active Directory.
It's a single static binary with no runtime dependencies and runs on Linux, macOS and Windows.

It supports all three LAPS storage formats and picks the right one per computer:

| Source              | AD attribute               | Notes                                              |
|---------------------|----------------------------|----------------------------------------------------|
| `EncryptedPassword` | `msLAPS-EncryptedPassword` | Windows LAPS, DPAPI-NG encrypted (decrypted locally) |
| `CleartextPassword` | `msLAPS-Password`          | Windows LAPS, unencrypted                          |
| `Legacy`            | `ms-Mcs-AdmPwd`            | Legacy Microsoft LAPS                              |

## Installation

Download the archive for your platform from the
[Releases](../../releases) page, extract it and put `laps-cli` somewhere on your
`PATH`. `SHA256SUMS` lists the checksums of all archives.

With Go installed, you can also build and install it directly:

```sh
go install github.com/jankkm/laps-cli@latest
```

## Usage

```sh
export LAPS_PASSWORD='…'          # or --password-stdin, or an interactive prompt
laps-cli -d corp.example.com -s dc01.corp.example.com -u admin PC01
```

Look up several computers at once. This takes a single LDAP search, and usually a single
key request for encrypted passwords:

```sh
laps-cli -d corp.example.com -u admin PC01 PC02 PC03
laps-cli -d corp.example.com -u admin PC01,PC02,PC03
laps-cli -d corp.example.com -u admin - < computers.txt
```

A name containing a dot is matched against `dNSHostName`, otherwise against the
computer's account name.

### Output

- **Default:** one password per line, in input order. A computer that can't be
  read gives an empty line, so the lines stay aligned with the input, and its
  error goes to stderr.
- **`--json`:** an array of
  `{computer, password, account, expiry, updated, source, error}`.

Exit status: `0` all found, `1` some computers failed, `2` usage, connection or
authentication error.

### Options

Every connection option can also be set with an environment variable, which keeps
credentials out of the command line and shell history.

| Flag | Env | Description |
|---|---|---|
| `-d, --domain` | `LAPS_DOMAIN` | AD domain (also used to derive the search base) |
| `-s, --dc` | `LAPS_DC` | Domain controller FQDN (default: the domain name) |
| `-u, --user` | `LAPS_USER` | `user`, `user@domain` or `DOMAIN\user` |
| `-p, --password` | `LAPS_PASSWORD` | Password (a flag is visible in the process list; prefer the env var) |
| `--password-stdin` | | Read the password from the first line of stdin |
| `--base` | `LAPS_BASE_DN` | LDAP search base |
| `--starttls` | `LAPS_STARTTLS` | LDAP + StartTLS on 389 instead of LDAPS on 636 |
| `--ca-file` | `LAPS_CA_FILE` | Additional trusted CA certificate(s) for LDAPS (PEM or DER), e.g. your internal root CA |
| `--insecure` | `LAPS_INSECURE` | Skip TLS certificate verification (testing only) |
| `--source` | | `auto` (default), `encrypted`, `cleartext`, `legacy` |
| `--timeout` | | Network timeout (default `10s`) |

## Requirements

- Your account needs read access to the LAPS attribute on the computer objects.
- For **encrypted** passwords, your account must also be in the LAPS *encryption
  principal* group (policy setting `ADPasswordEncryptionPrincipal`, which
  defaults to Domain Admins). Otherwise the DC refuses to release the key.
- Network access to the DC:
  - LDAPS (636), or LDAP with StartTLS (389)
  - for encrypted passwords: RPC endpoint mapper (135) and the dynamic RPC ports (49152–65535)
- The DC's LDAPS certificate must be trusted, either by the operating system's trust
  store or through `--ca-file`.

## Limitations

- LDAP requires TLS (LDAPS or StartTLS). A DC without a certificate can't be used yet.
- RPC authentication for encrypted passwords uses NTLM. Domains that block NTLM
  entirely would need Kerberos support, which isn't implemented yet.
- Only the current password is returned. Password history and DSRM passwords on domain
  controllers aren't supported.
- Only `SID=` protection descriptors are supported, which is what Windows LAPS uses.

## How encrypted passwords are decrypted

`msLAPS-EncryptedPassword` is a DPAPI-NG blob (CMS EnvelopedData). laps-cli
parses it, asks the DC for the matching group key with **MS-GKDI `GetKey`** over
NTLM-authenticated, encrypted DCE/RPC, then derives the key-encryption key
locally (SP800-108 KDF, plus DH/ECDH where needed) and decrypts with AES key
unwrap and AES-256-GCM. Blobs that share a root key and L0 index are decrypted
with one `GetKey` call, because older keys can be derived from newer ones.

No key material is written to disk.

## Building

Requires Go 1.26 or later.

```sh
make build     # ./laps-cli for the current platform
make test      # vet + unit tests (includes Windows-generated DPAPI-NG test vectors)
make release   # dist/: archives for Linux, macOS and Windows (amd64 + arm64)
```

Each release archive contains the binary, `LICENSE` and `THIRD_PARTY_NOTICES`.

### Releasing

laps-cli uses [semantic versioning](https://semver.org). The `VERSION` file (for example
`0.9.0`) is the single source of truth, and it's embedded into the binary
(`laps-cli --version`). Git tags carry a `v` prefix (`v0.9.0`), as Go modules expect.

1. Update `VERSION` (and run `make notices` if dependencies changed), then commit.
2. Tag the commit with `v` plus the version and push the tag:

   ```sh
   git tag "v$(cat VERSION)" && git push origin "v$(cat VERSION)"
   ```

The release workflow checks that the tag matches `VERSION` and runs the full CI (see
below). Only if that passes does it build Linux, macOS and Windows archives for amd64
and arm64 and publish them, with checksums, as a GitHub release.

### CI

CI runs on every push to `main` and on every pull request, except changes that touch
only documentation. It runs vet and the tests on Linux, macOS and Windows,
checks formatting, and checks that `THIRD_PARTY_NOTICES` is current. Dependabot
opens a weekly pull request for Go module and GitHub Actions updates. When a
dependency changes, run `make notices` and commit the result.

## License and credits

laps-cli is released under the [MIT License](LICENSE).

The DPAPI-NG / MS-GKDI implementation in `dpaping/` is ported from
[dpapi-ng](https://github.com/jborean93/dpapi-ng) by Jordan Borean (MIT). It also
draws on Microsoft's published protocol specifications ([MS-GKDI], [MS-DTYP],
RFC 3394, RFC 5652, NIST SP800-108 and SP800-56A). RPC transport is provided by
[go-msrpc](https://github.com/oiweiwei/go-msrpc) and LDAP by
[go-ldap](https://github.com/go-ldap/ldap).

Full third-party notices are in [THIRD_PARTY_NOTICES](THIRD_PARTY_NOTICES). Include
that file whenever you redistribute the binary, and regenerate it with `make notices`
after changing dependencies.

LAPS, Windows and Active Directory are trademarks of Microsoft Corporation. This
project is not affiliated with or endorsed by Microsoft.

[MS-GKDI]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gkdi/
[MS-DTYP]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/

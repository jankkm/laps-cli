#!/bin/sh
# SPDX-License-Identifier: MIT
#
# Generates THIRD_PARTY_NOTICES from the modules compiled into the binaries for
# all release platforms, plus the Go standard library and the dpapi-ng port credit.
# Usage: scripts/gen-notices.sh > THIRD_PARTY_NOTICES
set -eu
cd "$(dirname "$0")/.."

sep() { printf '\n================================================================================\n'; }

cat <<'HDR'
laps-cli includes third-party software. Their copyright notices and license
terms follow. Each component remains under its own license.
HDR

sep
cat <<'DPAPI'
dpapi-ng (https://github.com/jborean93/dpapi-ng)
Parts of dpaping/ are ported from dpapi-ng, and dpaping/testdata/ contains its
test vectors.

MIT License

Copyright (c) 2023 Jordan Borean, Red Hat

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
DPAPI

sep
printf 'The Go Programming Language (https://go.dev)\n\n'
goroot=$(go env GOROOT)
for f in "$goroot/LICENSE" "$goroot/../LICENSE"; do
	[ -f "$f" ] && { cat "$f"; break; }
done || { echo "ERROR: Go LICENSE not found" >&2; exit 1; }

for os in linux darwin windows; do
	GOOS=$os go list -deps -f '{{with .Module}}{{if not .Main}}{{.Path}} {{.Version}} {{.Dir}}{{end}}{{end}}' .
done |
	sort -u |
	while read -r path ver dir; do
		sep
		printf '%s %s (https://%s)\n' "$path" "$ver" "$path"
		case "$path" in
		github.com/hashicorp/go-uuid)
			printf 'Licensed under the Mozilla Public License 2.0. Unmodified source code is\navailable at https://github.com/hashicorp/go-uuid/tree/%s\n' "$ver" ;;
		esac
		printf '\n'
		found=0
		for f in "$dir"/LICENSE* "$dir"/LICENCE* "$dir"/COPYING* "$dir"/NOTICE*; do
			[ -f "$f" ] || continue
			cat "$f"
			printf '\n'
			found=1
		done
		[ "$found" = 1 ] || { echo "ERROR: no license file for $path" >&2; exit 1; }
	done

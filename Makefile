# SPDX-License-Identifier: MIT
# The version lives in the VERSION file and is embedded into the binary.
VERSION   := $(shell cat VERSION)
LDFLAGS   := -s -w
GOBUILD   := CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)"
PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64
DOCS      := LICENSE THIRD_PARTY_NOTICES README.md

.PHONY: build test notices release clean

build:
	$(GOBUILD) -o laps-cli .

test:
	go vet ./...
	go test ./...

# Regenerate after changing dependencies; ship it with every binary.
notices:
	scripts/gen-notices.sh > THIRD_PARTY_NOTICES

# One archive per platform in dist/, each with LICENSE and THIRD_PARTY_NOTICES.
release: test notices
	rm -rf dist && mkdir -p dist
	@set -e; for p in $(PLATFORMS); do \
		os=$${p%/*}; arch=$${p#*/}; name=laps-cli-$(VERSION)-$$os-$$arch; ext=; \
		[ $$os = windows ] && ext=.exe; \
		mkdir -p dist/$$name; \
		echo "building $$name"; \
		GOOS=$$os GOARCH=$$arch $(GOBUILD) -o dist/$$name/laps-cli$$ext .; \
		cp $(DOCS) dist/$$name/; \
		if [ $$os = windows ]; then (cd dist && zip -qr $$name.zip $$name); \
		else tar -C dist -czf dist/$$name.tar.gz $$name; fi; \
		rm -rf dist/$$name; \
	done

clean:
	rm -rf dist laps-cli

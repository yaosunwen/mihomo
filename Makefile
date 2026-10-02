NAME=mihomo
BINDIR=bin
BRANCH=$(shell git branch --show-current)
ifeq ($(BRANCH),Alpha)
VERSION=alpha-$(shell git rev-parse --short HEAD)
else ifeq ($(BRANCH),Beta)
VERSION=beta-$(shell git rev-parse --short HEAD)
else ifeq ($(BRANCH),)
VERSION=$(shell git describe --tags)
else
VERSION=$(shell git rev-parse --short HEAD)
endif

BUILDTIME=$(shell date -u)
GOBUILD=CGO_ENABLED=0 go build -tags with_gvisor -trimpath -ldflags '-X "github.com/metacubex/mihomo/constant.Version=$(VERSION)" \
		-X "github.com/metacubex/mihomo/constant.BuildTime=$(BUILDTIME)" \
		-w -s -buildid='

# cgo + libssl variant. Switches the OpenVPN control channel from
# crypto/tls (which omits DHE-RSA cipher suites, see golang/go#7758)
# to libssl via the transport/openvpn/libssl package. Requires a
# libssl installation discoverable by pkg-config; macOS Homebrew's
# `openssl@3` formula exposes the right pkg-config file at
# /opt/homebrew/opt/openssl@3/lib/pkgconfig.
#
# The resulting binary dynamically links libssl/libcrypto, so it is
# NOT a single-file distribution. The default build (GOBUILD above)
# remains the CGO_ENABLED=0 single-binary release path; this target
# is opt-in for operators who need DHE-RSA / TLS-DHE-* cipher suites.
CGO_BUILD=PKG_CONFIG_PATH=$(PKG_CONFIG_PATH) CGO_ENABLED=1 go build -tags 'with_gvisor with_libssl' -trimpath -ldflags '-X "github.com/metacubex/mihomo/constant.Version=$(VERSION)" \
		-X "github.com/metacubex/mihomo/constant.BuildTime=$(BUILDTIME)" \
		-w -s -buildid='

PLATFORM_LIST = \
	darwin-386 \
	darwin-amd64-compatible \
	darwin-amd64 \
	darwin-amd64-v1 \
	darwin-amd64-v2 \
	darwin-amd64-v3 \
	darwin-arm64 \
	linux-386 \
	linux-amd64-compatible \
	linux-amd64 \
	linux-amd64-v1 \
	linux-amd64-v2 \
	linux-amd64-v3 \
	linux-armv5 \
	linux-armv6 \
	linux-armv7 \
	linux-arm64 \
	linux-mips64 \
	linux-mips64le \
	linux-mips-softfloat \
	linux-mips-hardfloat \
	linux-mipsle-softfloat \
	linux-mipsle-hardfloat \
	linux-riscv64 \
	linux-loong64 \
	android-arm64 \
	freebsd-386 \
	freebsd-amd64 \
	freebsd-arm64

WINDOWS_ARCH_LIST = \
	windows-386 \
	windows-amd64-compatible \
	windows-amd64 \
	windows-amd64-v1 \
	windows-amd64-v2 \
	windows-amd64-v3 \
	windows-arm64 \
    windows-arm32v7

all:linux-amd64-v3 linux-arm64\
	darwin-amd64-v3 darwin-arm64\
 	windows-amd64-v3 windows-arm64\


darwin-all: darwin-amd64-v3 darwin-arm64

docker:
	GOAMD64=v1 $(GOBUILD) -o $(BINDIR)/$(NAME)-$@

darwin-386:
	GOARCH=386 GOOS=darwin $(GOBUILD) -o $(BINDIR)/$(NAME)-$@

darwin-amd64-compatible:
	GOARCH=amd64 GOOS=darwin GOAMD64=v1 $(GOBUILD) -o $(BINDIR)/$(NAME)-$@

darwin-amd64:
	GOARCH=amd64 GOOS=darwin GOAMD64=v3 $(GOBUILD) -o $(BINDIR)/$(NAME)-$@

darwin-amd64-v1:
	GOARCH=amd64 GOOS=darwin GOAMD64=v1 $(GOBUILD) -o $(BINDIR)/$(NAME)-$@

darwin-amd64-v2:
	GOARCH=amd64 GOOS=darwin GOAMD64=v2 $(GOBUILD) -o $(BINDIR)/$(NAME)-$@

darwin-amd64-v3:
	GOARCH=amd64 GOOS=darwin GOAMD64=v3 $(GOBUILD) -o $(BINDIR)/$(NAME)-$@

darwin-arm64:
	GOARCH=arm64 GOOS=darwin $(GOBUILD) -o $(BINDIR)/$(NAME)-$@

# cgo + libssl build. PKG_CONFIG_PATH must point at the directory
# holding openssl.pc. On macOS Homebrew: `brew install openssl@3`
# (auto-installed) gives `/opt/homebrew/opt/openssl@3/lib/pkgconfig`.
# Override on the command line to point at a different prefix:
#
#   make darwin-arm64-libssl PKG_CONFIG_PATH=/path/to/openssl/lib/pkgconfig
#
# The resulting binary is dynamically linked against libssl/libcrypto
# from the prefix above; the runtime loader must be able to find the
# dylib (Homebrew's Homebrew dynamic loader config usually does).
darwin-arm64-libssl:
	GOARCH=arm64 GOOS=darwin PKG_CONFIG_PATH=$(PKG_CONFIG_PATH) $(CGO_BUILD) -o $(BINDIR)/$(NAME)-$@

linux-386:
	GOARCH=386 GOOS=linux $(GOBUILD) -o $(BINDIR)/$(NAME)-$@

linux-amd64-compatible:
	GOARCH=amd64 GOOS=linux GOAMD64=v1 $(GOBUILD) -o $(BINDIR)/$(NAME)-$@

linux-amd64:
	GOARCH=amd64 GOOS=linux GOAMD64=v3 $(GOBUILD) -o $(BINDIR)/$(NAME)-$@

linux-amd64-v1:
	GOARCH=amd64 GOOS=linux GOAMD64=v1 $(GOBUILD) -o $(BINDIR)/$(NAME)-$@

linux-amd64-v2:
	GOARCH=amd64 GOOS=linux GOAMD64=v2 $(GOBUILD) -o $(BINDIR)/$(NAME)-$@

linux-amd64-v3:
	GOARCH=amd64 GOOS=linux GOAMD64=v3 $(GOBUILD) -o $(BINDIR)/$(NAME)-$@

linux-arm64:
	GOARCH=arm64 GOOS=linux $(GOBUILD) -o $(BINDIR)/$(NAME)-$@

linux-armv5:
	GOARCH=arm GOOS=linux GOARM=5 $(GOBUILD) -o $(BINDIR)/$(NAME)-$@

linux-armv6:
	GOARCH=arm GOOS=linux GOARM=6 $(GOBUILD) -o $(BINDIR)/$(NAME)-$@

linux-armv7:
	GOARCH=arm GOOS=linux GOARM=7 $(GOBUILD) -o $(BINDIR)/$(NAME)-$@

linux-mips-softfloat:
	GOARCH=mips GOMIPS=softfloat GOOS=linux $(GOBUILD) -o $(BINDIR)/$(NAME)-$@

linux-mips-hardfloat:
	GOARCH=mips GOMIPS=hardfloat GOOS=linux $(GOBUILD) -o $(BINDIR)/$(NAME)-$@

linux-mipsle-softfloat:
	GOARCH=mipsle GOMIPS=softfloat GOOS=linux $(GOBUILD) -o $(BINDIR)/$(NAME)-$@

linux-mipsle-hardfloat:
	GOARCH=mipsle GOMIPS=hardfloat GOOS=linux $(GOBUILD) -o $(BINDIR)/$(NAME)-$@

linux-mips64:
	GOARCH=mips64 GOOS=linux $(GOBUILD) -o $(BINDIR)/$(NAME)-$@

linux-mips64le:
	GOARCH=mips64le GOOS=linux $(GOBUILD) -o $(BINDIR)/$(NAME)-$@

linux-riscv64:
	GOARCH=riscv64 GOOS=linux $(GOBUILD) -o $(BINDIR)/$(NAME)-$@
	
linux-loong64:
	GOARCH=loong64 GOOS=linux $(GOBUILD) -o $(BINDIR)/$(NAME)-$@

android-arm64:
	GOARCH=arm64 GOOS=android $(GOBUILD) -o $(BINDIR)/$(NAME)-$@

freebsd-386:
	GOARCH=386 GOOS=freebsd $(GOBUILD) -o $(BINDIR)/$(NAME)-$@

freebsd-amd64:
	GOARCH=amd64 GOOS=freebsd GOAMD64=v3 $(GOBUILD) -o $(BINDIR)/$(NAME)-$@

freebsd-arm64:
	GOARCH=arm64 GOOS=freebsd $(GOBUILD) -o $(BINDIR)/$(NAME)-$@

windows-386:
	GOARCH=386 GOOS=windows $(GOBUILD) -o $(BINDIR)/$(NAME)-$@.exe

windows-amd64-compatible:
	GOARCH=amd64 GOOS=windows GOAMD64=v1 $(GOBUILD) -o $(BINDIR)/$(NAME)-$@.exe

windows-amd64:
	GOARCH=amd64 GOOS=windows GOAMD64=v3 $(GOBUILD) -o $(BINDIR)/$(NAME)-$@.exe

windows-amd64-v1:
	GOARCH=amd64 GOOS=windows GOAMD64=v1 $(GOBUILD) -o $(BINDIR)/$(NAME)-$@.exe

windows-amd64-v2:
	GOARCH=amd64 GOOS=windows GOAMD64=v2 $(GOBUILD) -o $(BINDIR)/$(NAME)-$@.exe

windows-amd64-v3:
	GOARCH=amd64 GOOS=windows GOAMD64=v3 $(GOBUILD) -o $(BINDIR)/$(NAME)-$@.exe

windows-arm64:
	GOARCH=arm64 GOOS=windows $(GOBUILD) -o $(BINDIR)/$(NAME)-$@.exe

windows-arm32v7:
	GOARCH=arm GOOS=windows GOARM=7 $(GOBUILD) -o $(BINDIR)/$(NAME)-$@.exe

gz_releases=$(addsuffix .gz, $(PLATFORM_LIST))
zip_releases=$(addsuffix .zip, $(WINDOWS_ARCH_LIST))

$(gz_releases): %.gz : %
	chmod +x $(BINDIR)/$(NAME)-$(basename $@)
	gzip -f -S -$(VERSION).gz $(BINDIR)/$(NAME)-$(basename $@)

$(zip_releases): %.zip : %
	zip -m -j $(BINDIR)/$(NAME)-$(basename $@)-$(VERSION).zip $(BINDIR)/$(NAME)-$(basename $@).exe

all-arch: $(PLATFORM_LIST) $(WINDOWS_ARCH_LIST)

releases: $(gz_releases) $(zip_releases)

vet:
	go test ./...

lint:
	golangci-lint run ./...

clean:
	rm $(BINDIR)/*

CLANG ?= clang-14
CFLAGS := -O2 -g -Wall -Werror $(CFLAGS)


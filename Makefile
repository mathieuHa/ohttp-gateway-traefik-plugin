.PHONY: default lint test yaegi_test e2e keygen clean

export GO111MODULE=on

# Packages interpreted by Yaegi when Traefik loads the plugin.
PLUGIN_PACKAGES := . pkg/hpke pkg/bhttp pkg/ohttp

default: lint test

lint:
	golangci-lint run ./...
	cd tests/e2e && golangci-lint run ./...

test:
	go test -race -cover ./...

# Runs the unit tests with Yaegi, the interpreter embedded in Traefik. The
# repository must be located at $GOPATH/src/github.com/mathieuHa/ohttp-gateway-traefik-plugin.
yaegi_test:
	@set -e; for pkg in $(PLUGIN_PACKAGES); do \
		echo "yaegi test $$pkg"; \
		(cd $$pkg && yaegi test .); \
	done

# End-to-end tests against a real Traefik binary (TRAEFIK_VERSION=vX.Y.Z to pick one).
e2e:
	./tests/e2e/run.sh

keygen:
	go run ./cmd/ohttp-keygen

clean:
	rm -rf tests/e2e/.cache

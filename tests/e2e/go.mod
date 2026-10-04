module github.com/mathieuHa/ohttp-gateway-traefik-plugin/tests/e2e

go 1.22

replace github.com/mathieuHa/ohttp-gateway-traefik-plugin => ../..

require (
	github.com/chris-wood/ohttp-go v0.0.0-20260205154755-776f22a178b8
	github.com/mathieuHa/ohttp-gateway-traefik-plugin v0.0.0
)

require (
	github.com/cloudflare/circl v1.3.3-0.20230418220640-795540340d5c // indirect
	golang.org/x/crypto v0.3.1-0.20221117191849-2c476679df9a // indirect
	golang.org/x/sys v0.3.0 // indirect
)

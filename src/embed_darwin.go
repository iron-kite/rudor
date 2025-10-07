//go:build darwin

package main

import _ "embed"

//go:embed resources/binaries/cdxgen-darwin-arm64-slim
var embeddedBinary []byte

const binaryName = "cdxgen-darwin-arm64-slim"

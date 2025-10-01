//go:build linux

package main

import _ "embed"

//go:embed resources/binaries/cdxgen-linux-amd64-slim
var embeddedBinary []byte

const binaryName = "cdxgen-linux-amd64-slim"

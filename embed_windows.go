//go:build windows

package main

import _ "embed"

//go:embed resources/binaries/cdxgen-windows-amd64-slim.exe
var embeddedBinary []byte

const binaryName = "cdxgen-windows-amd64-slim.exe"
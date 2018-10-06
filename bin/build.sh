#!/bin/bash -eu

source /build-common.sh

BINARY_NAME="holepunch"
COMPILE_IN_DIRECTORY="cmd/holepunch"
BINTRAY_PROJECT="function61/holepunch-client"

INCLUDE_WINDOWS="true"

standardBuildProcess

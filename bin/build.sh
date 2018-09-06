#!/bin/bash -eu

run() {
	fn="$1"

	echo "# $fn"

	"$fn"
}

downloadDependencies() {
	dep ensure
}

unitTests() {
	go test ./...
}

staticAnalysis() {
	go vet ./...
}

buildLinuxArm() {
	GOOS=linux GOARCH=arm go build -o rel/holepunch_linux-arm
}

buildLinuxAmd64() {
	GOOS=linux GOARCH=amd64 go build -o rel/holepunch_linux-amd64
}

buildWindowsAmd64() {
	GOOS=windows GOARCH=amd64 go build -o rel/holepunch.exe
}

uploadBuildArtefacts() {
	# the CLI breaks automation unless opt-out..
	export JFROG_CLI_OFFER_CONFIG=false

	jfrog-cli bt upload \
		"--user=joonas" \
		"--key=$BINTRAY_APIKEY" \
		--publish=true \
		'rel/*' \
		"function61/holepunch-client/main/$FRIENDLY_REV_ID" \
		"$FRIENDLY_REV_ID/"
}

rm -rf rel
mkdir rel

run downloadDependencies

run staticAnalysis

run unitTests

run buildLinuxArm

run buildLinuxAmd64

run buildWindowsAmd64

if [ "${PUBLISH_ARTEFACTS:-''}" = "true" ]; then
	run uploadBuildArtefacts
fi

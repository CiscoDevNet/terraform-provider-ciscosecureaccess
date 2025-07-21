#!/usr/bin/env bash
VERSION=$(ls terraform-provider-ciscosecureaccess* |sed 's/.*_v//')
GOOS=$(uname -s | tr "[:upper:]" "[:lower:]")
GOARCH=$(uname -m | tr "[:upper:]" "[:lower:]")
if [[ $GOARCH == "x86_64" ]];then
GOARCH=amd64
fi
INSTALL_PATH=./terraform/terraform.d/plugins/github.com/ciscodevnet/ciscosecureaccess/${VERSION}/${GOOS}_${GOARCH}/
mkdir -p "${INSTALL_PATH}"
cp ./terraform-provider-ciscosecureaccess* "${INSTALL_PATH}"
cp examples/complex/secure-access.tf terraform/

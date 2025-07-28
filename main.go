// Copyright 2025 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"context"
	"log"

	"github.com/CiscoDevNet/terraform-provider-ciscosecureaccess/internal/provider"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
)

var (
	// these will be set by the goreleaser configuration

	// to appropriate values for the compiled binary
	version string = "dev"
)

func main() {
	err := providerserver.Serve(
		context.Background(),
		provider.New(version),
		providerserver.ServeOpts{
			Address: "registry.terraform.io/<namespace>/<provider_name>",
		},
	)

	if err != nil {
		log.Fatal(err)
	}
}

// Copyright 2025 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"os"
	"testing"

	"github.com/CiscoDevNet/go-ciscosecureaccess/client"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/stretchr/testify/require"
)

var testAccCiscoSecureAccessProviderFactories = map[string]func() (tfprotov6.ProviderServer, error){
	"ciscosecureaccess": providerserver.NewProtocol6WithError(New("0.0.1")()),
}

func testAccPreCheck(t *testing.T) {
	// Code can be added here as pre-execution steps to all unit tests
}

func testClientFactory(t *testing.T) *client.SSEClientFactory {
	keyId, ok := os.LookupEnv("CISCOSECUREACCESS_KEY_ID")
	require.True(t, ok, "missing CISCOSECUREACCESS_KEY_ID")
	keySecret, ok := os.LookupEnv("CISCOSECUREACCESS_KEY_SECRET")
	require.True(t, ok, "missing CISCOSECUREACCESS_KEY_SECRET")

	return &client.SSEClientFactory{KeyId: keyId, KeySecret: keySecret}

}

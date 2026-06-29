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

var testSSEClientFactory *client.SSEClientFactory

var testAccCiscoSecureAccessProviderFactories = map[string]func() (tfprotov6.ProviderServer, error){
	"ciscosecureaccess": providerserver.NewProtocol6WithError(New("0.0.1")()),
}

func testAccPreCheck(t *testing.T) {
	if os.Getenv("CISCOSECUREACCESS_KEY_ID") == "" {
		t.Skip("CISCOSECUREACCESS_KEY_ID must be set for acceptance tests")
	}
	if os.Getenv("CISCOSECUREACCESS_KEY_SECRET") == "" {
		t.Skip("CISCOSECUREACCESS_KEY_SECRET must be set for acceptance tests")
	}
}

func testAccMutationPreCheck(t *testing.T) {
	t.Helper()
	testAccPreCheck(t)

	testOrgID := os.Getenv("CISCOSECUREACCESS_TEST_ORG_ID")
	allowMutation := os.Getenv("CISCOSECUREACCESS_TEST_ALLOW_MUTATION")
	if testOrgID != "8376136" || allowMutation != testOrgID {
		t.Fatalf(
			"mutating acceptance tests require CISCOSECUREACCESS_TEST_ORG_ID and CISCOSECUREACCESS_TEST_ALLOW_MUTATION to both equal 8376136",
		)
	}
}

func testClientFactory(t *testing.T) *client.SSEClientFactory {
	t.Helper()

	keyId := os.Getenv("CISCOSECUREACCESS_KEY_ID")
	if keyId == "" {
		t.Skip("CISCOSECUREACCESS_KEY_ID must be set for acceptance tests")
	}
	keySecret := os.Getenv("CISCOSECUREACCESS_KEY_SECRET")
	if keySecret == "" {
		t.Skip("CISCOSECUREACCESS_KEY_SECRET must be set for acceptance tests")
	}

	if testSSEClientFactory == nil {
		var err error
		testSSEClientFactory, err = client.NewSSEClientFactory(keyId, keySecret, "")
		require.NoError(t, err, "failed to create SSEClientFactory")
	}

	return testSSEClientFactory
}

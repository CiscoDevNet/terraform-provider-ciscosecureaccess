// Copyright 2025 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"fmt"
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

// Test constants for global settings tests
const (
	testGlobalSettingsResourceName = "ciscosecureaccess_global_settings.global_settings"
	testGlobalSettingsEnvVar       = "CISCOSECUREACCESS_TEST_GLOBAL_DECRYPTION"
)

// TestGlobalSettingsResource_enabled tests enabling global decryption
func TestGlobalSettingsResource_enabled(t *testing.T) {
	if os.Getenv(testGlobalSettingsEnvVar) != "true" {
		t.Skipf("Skipping test for global settings enablement as it is controlled by environment variable %s", testGlobalSettingsEnvVar)
	}
	rateLimitedTest(t, func() {
		runGlobalSettingsEnablementTest(t, true)
	}, minWaitTime)
}

// TestGlobalSettingsResource_disabled tests disabling global decryption
func TestGlobalSettingsResource_disabled(t *testing.T) {
	if os.Getenv(testGlobalSettingsEnvVar) != "true" {
		t.Skipf("Skipping test for global settings enablement as it is controlled by environment variable %s", testGlobalSettingsEnvVar)
	}
	rateLimitedTest(t, func() {
		runGlobalSettingsEnablementTest(t, false)
	}, minWaitTime)
}

// runGlobalSettingsEnablementTest runs the test for global settings with the specified enablement state
func runGlobalSettingsEnablementTest(t *testing.T, enabled bool) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccCiscoSecureAccessProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testGlobalSettingsConfig(enabled),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(testGlobalSettingsResourceName, "id"),
					resource.TestCheckResourceAttr(testGlobalSettingsResourceName, "enable_global_decryption", fmt.Sprintf("%t", enabled)),
				),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(testGlobalSettingsResourceName, tfjsonpath.New("enable_global_decryption"), knownvalue.Bool(enabled)),
				},
			},
		},
	})
}

// Helper functions

// testGlobalSettingsConfig returns a configuration for global settings with the specified enablement state
func testGlobalSettingsConfig(enabled bool) string {
	return fmt.Sprintf(`
resource "ciscosecureaccess_global_settings" "global_settings" {
  enable_global_decryption = %t
}`, enabled)
}

// Copyright 2025 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

// Test constants for site resource tests
const (
	testSiteResourceName  = "ciscosecureaccess_site.test_resource"
	testSiteNamePrefix    = "tfAcc"
	testSiteUpdatedSuffix = "updated"
)

// generateSiteTestName creates a unique test name for site tests
func generateSiteTestName(suffix string) string {
	return fmt.Sprintf("%s%s-%s", testSiteNamePrefix, acctest.RandStringFromCharSet(8, acctest.CharSetAlphaNum), suffix)
}

func TestSiteResource_basic(t *testing.T) {
	rateLimitedTest(t, func() {
		testName := generateSiteTestName("basic")

		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { testAccPreCheck(t) },
			ProtoV6ProviderFactories: testAccCiscoSecureAccessProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: testAccSiteBasicConfig(testName),
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttrSet(testSiteResourceName, "id"),
						resource.TestCheckResourceAttr(testSiteResourceName, "name", testName),
					),
					ConfigStateChecks: []statecheck.StateCheck{
						statecheck.ExpectKnownValue(testSiteResourceName, tfjsonpath.New("name"), knownvalue.StringExact(testName)),
						statecheck.ExpectKnownValue(testSiteResourceName, tfjsonpath.New("is_default"), knownvalue.Bool(false)),
					},
				},
			},
		})
	}, minWaitTime)
}

func TestSiteResource_update(t *testing.T) {
	rateLimitedTest(t, func() {
		testName := generateSiteTestName("update")
		updatedName := generateSiteTestName(testSiteUpdatedSuffix)

		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { testAccPreCheck(t) },
			ProtoV6ProviderFactories: testAccCiscoSecureAccessProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: testAccSiteBasicConfig(testName),
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttrSet(testSiteResourceName, "id"),
						resource.TestCheckResourceAttr(testSiteResourceName, "name", testName),
					),
				},
				{
					Config: testAccSiteBasicConfig(updatedName),
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttrSet(testSiteResourceName, "id"),
						resource.TestCheckResourceAttr(testSiteResourceName, "name", updatedName),
					),
					ConfigStateChecks: []statecheck.StateCheck{
						statecheck.ExpectKnownValue(testSiteResourceName, tfjsonpath.New("name"), knownvalue.StringExact(updatedName)),
					},
				},
			},
		})
	}, minWaitTime)
}

func testAccSiteBasicConfig(name string) string {
	return fmt.Sprintf(`
resource "ciscosecureaccess_site" "test_resource" {
  name = %q
}
`, name)
}

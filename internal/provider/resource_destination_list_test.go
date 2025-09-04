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

// Test constants for destination list tests
const (
	testDestinationListResourceName = "ciscosecureaccess_destination_list.acceptance_list"
	testDestinationListNamePrefix   = "tfAcc"
)

func TestAccDestinationList_basic(t *testing.T) {
	rateLimitedTest(t, func() {
		testName := generateDestinationListTestName("basic")

		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { testAccPreCheck(t) },
			ProtoV6ProviderFactories: testAccCiscoSecureAccessProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: testAccDestinationListBasicConfig(testName),
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttrSet(testDestinationListResourceName, "id"),
						resource.TestCheckResourceAttr(testDestinationListResourceName, "name", testName),
						resource.TestCheckResourceAttr(testDestinationListResourceName, "destinations.#", "2"),
					),
					ConfigStateChecks: []statecheck.StateCheck{
						statecheck.ExpectKnownValue(testDestinationListResourceName, tfjsonpath.New("name"), knownvalue.StringExact(testName)),
						statecheck.ExpectKnownValue(testDestinationListResourceName, tfjsonpath.New("destinations"), knownvalue.SetSizeExact(2)),
					},
				},
			},
		})
	}, minWaitTime)
}

func TestAccDestinationList_update(t *testing.T) {
	rateLimitedTest(t, func() {
		testName := generateDestinationListTestName("update")
		updatedTestName := testName + "_updated"

		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { testAccPreCheck(t) },
			ProtoV6ProviderFactories: testAccCiscoSecureAccessProviderFactories,
			Steps: []resource.TestStep{
				{
					// Create initial resource
					Config: testAccDestinationListBasicConfig(testName),
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttrSet(testDestinationListResourceName, "id"),
						resource.TestCheckResourceAttr(testDestinationListResourceName, "name", testName),
					),
				},
				{
					// Update the resource name
					Config: testAccDestinationListBasicConfig(updatedTestName),
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttrSet(testDestinationListResourceName, "id"),
						resource.TestCheckResourceAttr(testDestinationListResourceName, "name", updatedTestName),
					),
					ConfigStateChecks: []statecheck.StateCheck{
						statecheck.ExpectKnownValue(testDestinationListResourceName, tfjsonpath.New("name"), knownvalue.StringExact(updatedTestName)),
					},
				},
			},
		})
	}, minWaitTime)
}

func TestAccDestinationList_addDestination(t *testing.T) {
	rateLimitedTest(t, func() {
		testName := generateDestinationListTestName("add_destination")

		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { testAccPreCheck(t) },
			ProtoV6ProviderFactories: testAccCiscoSecureAccessProviderFactories,
			Steps: []resource.TestStep{
				{
					// Create initial resource with 2 destinations
					Config: testAccDestinationListBasicConfig(testName),
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttrSet(testDestinationListResourceName, "id"),
						resource.TestCheckResourceAttr(testDestinationListResourceName, "name", testName),
						resource.TestCheckResourceAttr(testDestinationListResourceName, "destinations.#", "2"),
					),
				},
				{
					// Add a third destination to test state update issue
					Config: testAccDestinationListAddDestinationConfig(testName),
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttrSet(testDestinationListResourceName, "id"),
						resource.TestCheckResourceAttr(testDestinationListResourceName, "name", testName),
						resource.TestCheckResourceAttr(testDestinationListResourceName, "destinations.#", "3"),
					),
					ConfigStateChecks: []statecheck.StateCheck{
						statecheck.ExpectKnownValue(testDestinationListResourceName, tfjsonpath.New("destinations"), knownvalue.SetSizeExact(3)),
					},
				},
			},
		})
	}, minWaitTime)
}

// Helper functions

// generateDestinationListTestName creates a unique test name with the given suffix
func generateDestinationListTestName(suffix string) string {
	return fmt.Sprintf("%s%s_%s", testDestinationListNamePrefix, acctest.RandStringFromCharSet(8, acctest.CharSetAlphaNum), suffix)
}

// Configuration generators

// testAccDestinationListBasicConfig returns a basic destination list configuration
func testAccDestinationListBasicConfig(name string) string {
	return fmt.Sprintf(`
resource "ciscosecureaccess_destination_list" "acceptance_list" {
    name = "%s"
    destinations = [
      {
        comment = "First test destination managed by TF"
        type = "ipv4"
        destination = "127.0.0.2"
      },
      {
        comment = "Second test destination managed by TF"
        type = "url"
        destination = "http://example.com/test"
      },
    ]
}`, name)
}

// testAccDestinationListAddDestinationConfig returns a configuration with an additional destination
func testAccDestinationListAddDestinationConfig(name string) string {
	return fmt.Sprintf(`
resource "ciscosecureaccess_destination_list" "acceptance_list" {
    name = "%s"
    destinations = [
      {
        comment = "First test destination managed by TF"
        type = "ipv4"
        destination = "127.0.0.2"
      },
      {
        comment = "Second test destination managed by TF"
        type = "url"
        destination = "http://example.com/test"
      },
      {
        comment = "Third test destination to test state update"
        type = "domain"
        destination = "foo.bar.baz"
      },
    ]
}`, name)
}

// Copyright 2025 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccZtnaProfilePrivateResourceMappings_basic(t *testing.T) {
	rateLimitedTest(t, func() {
		profileName := fmt.Sprintf("tfAccPrm%s", acctest.RandStringFromCharSet(6, acctest.CharSetAlphaNum))
		prName := fmt.Sprintf("tfAcc-pr-%s", acctest.RandStringFromCharSet(6, acctest.CharSetAlphaNum))

		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { testAccPreCheck(t) },
			ProtoV6ProviderFactories: testAccCiscoSecureAccessProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: testAccZtnaProfilePrivateResourceMappingsConfig(profileName, prName),
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttr("ciscosecureaccess_ztna_profile_private_resource_mappings.test", "private_resource_ids.#", "1"),
					),
				},
			},
		})
	}, minWaitTime)
}

func TestAccZtnaProfileInternetSteeringDestinationLists_basic(t *testing.T) {
	rateLimitedTest(t, func() {
		profileName := fmt.Sprintf("tfAccIsdl%s", acctest.RandStringFromCharSet(6, acctest.CharSetAlphaNum))
		dlName := fmt.Sprintf("tfAcc-dl-%s", acctest.RandStringFromCharSet(6, acctest.CharSetAlphaNum))

		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { testAccPreCheck(t) },
			ProtoV6ProviderFactories: testAccCiscoSecureAccessProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: testAccZtnaProfileInternetSteeringDestListsConfig(profileName, dlName),
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttr("ciscosecureaccess_ztna_profile_internet_steering_destination_lists.test", "destination_list.#", "1"),
					),
				},
			},
		})
	}, minWaitTime)
}

func TestAccZtnaProfileInternetSteeringExclusions_basic(t *testing.T) {
	rateLimitedTest(t, func() {
		profileName := fmt.Sprintf("tfAccIse%s", acctest.RandStringFromCharSet(6, acctest.CharSetAlphaNum))

		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { testAccPreCheck(t) },
			ProtoV6ProviderFactories: testAccCiscoSecureAccessProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: testAccZtnaProfileInternetSteeringExclusionsConfig(profileName),
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttr("ciscosecureaccess_ztna_profile_internet_steering_exclusions.test", "exclusion.#", "2"),
					),
				},
			},
		})
	}, minWaitTime)
}

func TestAccZtnaPrivateSteeringDestination_basic(t *testing.T) {
	rateLimitedTest(t, func() {
		profileName := fmt.Sprintf("tfAccPsd%s", acctest.RandStringFromCharSet(6, acctest.CharSetAlphaNum))

		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { testAccPreCheck(t) },
			ProtoV6ProviderFactories: testAccCiscoSecureAccessProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: testAccZtnaPrivateSteeringDestinationConfig(profileName),
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttrSet("ciscosecureaccess_ztna_private_steering_destination.test", "id"),
						resource.TestCheckResourceAttr("ciscosecureaccess_ztna_private_steering_destination.test", "endpoint", "*.test-psd.example.com"),
						resource.TestCheckResourceAttrSet("ciscosecureaccess_ztna_private_steering_destination.test", "endpoint_type"),
					),
				},
			},
		})
	}, minWaitTime)
}

func testAccZtnaProfilePrivateResourceMappingsConfig(profileName, prName string) string {
	return fmt.Sprintf(`
resource "ciscosecureaccess_ztna_profile" "test" {
  profile_name = %[1]q
  priority     = 1

  secure_private_access = {
    trusted_networks_enabled = false
    enforcement_pause = { enabled = false }
  }
  secure_internet_access = {
    steering_mode            = 0
    trusted_networks_enabled = false
    enforcement_pause = { enabled = false }
  }
  users_data  = { all_users_enabled = true }
  groups_data = { all_groups_enabled = true }
}

resource "ciscosecureaccess_private_resource" "test" {
  name         = %[2]q
  access_types = ["client"]
  description  = "Acc test resource for mapping"
  client_reachable_addresses = ["10.99.0.1"]
  addresses = [{
    addresses        = ["10.99.0.1"]
    traffic_selector = [{ ports = "443", protocol = "http/https" }]
  }]
}

resource "ciscosecureaccess_ztna_profile_private_resource_mappings" "test" {
  profile_id           = ciscosecureaccess_ztna_profile.test.id
  private_resource_ids = [ciscosecureaccess_private_resource.test.id]
}
`, profileName, prName)
}

func testAccZtnaProfileInternetSteeringDestListsConfig(profileName, dlName string) string {
	return fmt.Sprintf(`
resource "ciscosecureaccess_ztna_profile" "test" {
  profile_name = %[1]q
  priority     = 1

  secure_private_access = {
    trusted_networks_enabled = false
    enforcement_pause = { enabled = false }
  }
  secure_internet_access = {
    steering_mode            = 2
    trusted_networks_enabled = false
    enforcement_pause = { enabled = false }
  }
  users_data  = { all_users_enabled = true }
  groups_data = { all_groups_enabled = true }
}

resource "ciscosecureaccess_destination_list" "test" {
  name         = %[2]q
  destinations = []
  lifecycle { ignore_changes = [destinations] }
}

resource "ciscosecureaccess_ztna_profile_internet_steering_destination_lists" "test" {
  profile_id = ciscosecureaccess_ztna_profile.test.id

  destination_list = [{
    id         = ciscosecureaccess_destination_list.test.id
    exclusions = []
  }]
}
`, profileName, dlName)
}

func testAccZtnaProfileInternetSteeringExclusionsConfig(profileName string) string {
	return fmt.Sprintf(`
resource "ciscosecureaccess_ztna_profile" "test" {
  profile_name = %[1]q
  priority     = 1

  secure_private_access = {
    trusted_networks_enabled = false
    enforcement_pause = { enabled = false }
  }
  secure_internet_access = {
    steering_mode            = 1
    trusted_networks_enabled = false
    enforcement_pause = { enabled = false }
  }
  users_data  = { all_users_enabled = true }
  groups_data = { all_groups_enabled = true }
}

resource "ciscosecureaccess_ztna_profile_internet_steering_exclusions" "test" {
  profile_id = ciscosecureaccess_ztna_profile.test.id

  exclusion = [
    {
      destination = "*.opendnstest-acc.com"
      description = "Acceptance test exclusion 1"
    },
    {
      destination = "safe.internal-acc.com"
      description = "Acceptance test exclusion 2"
    }
  ]
}
`, profileName)
}

func testAccZtnaPrivateSteeringDestinationConfig(profileName string) string {
	return fmt.Sprintf(`
resource "ciscosecureaccess_ztna_profile" "test" {
  profile_name = %[1]q
  priority     = 1

  secure_private_access = {
    trusted_networks_enabled = false
    enforcement_pause = { enabled = false }
  }
  secure_internet_access = {
    steering_mode            = 0
    trusted_networks_enabled = false
    enforcement_pause = { enabled = false }
  }
  users_data  = { all_users_enabled = true }
  groups_data = { all_groups_enabled = true }
}

resource "ciscosecureaccess_ztna_private_steering_destination" "test" {
  profile_id = ciscosecureaccess_ztna_profile.test.id
  endpoint   = "*.test-psd.example.com"
  exclusions = ["public.test-psd.example.com"]
}
`, profileName)
}

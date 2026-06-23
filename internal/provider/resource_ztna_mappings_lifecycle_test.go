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

func TestAccZtnaProfilePrivateResourceMappings_update(t *testing.T) {
	rateLimitedTest(t, func() {
		profileName := fmt.Sprintf("tfAccPrmU%s", acctest.RandStringFromCharSet(6, acctest.CharSetAlphaNum))
		prName1 := fmt.Sprintf("tfAcc-pr1-%s", acctest.RandStringFromCharSet(6, acctest.CharSetAlphaNum))
		prName2 := fmt.Sprintf("tfAcc-pr2-%s", acctest.RandStringFromCharSet(6, acctest.CharSetAlphaNum))

		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { testAccPreCheck(t) },
			ProtoV6ProviderFactories: testAccCiscoSecureAccessProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: testAccZtnaProfilePrivateResourceMappings1Config(profileName, prName1),
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttr("ciscosecureaccess_ztna_profile_private_resource_mappings.test", "private_resource_ids.#", "1"),
					),
				},
				{
					Config: testAccZtnaProfilePrivateResourceMappings2Config(profileName, prName1, prName2),
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttr("ciscosecureaccess_ztna_profile_private_resource_mappings.test", "private_resource_ids.#", "2"),
					),
				},
			},
		})
	}, minWaitTime)
}

func TestAccZtnaProfileInternetSteeringExclusions_update(t *testing.T) {
	rateLimitedTest(t, func() {
		profileName := fmt.Sprintf("tfAccIseU%s", acctest.RandStringFromCharSet(6, acctest.CharSetAlphaNum))

		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { testAccPreCheck(t) },
			ProtoV6ProviderFactories: testAccCiscoSecureAccessProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: testAccZtnaProfileExclusionsStep1Config(profileName),
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttr("ciscosecureaccess_ztna_profile_internet_steering_exclusions.test", "exclusion.#", "1"),
					),
				},
				{
					Config: testAccZtnaProfileExclusionsStep2Config(profileName),
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttr("ciscosecureaccess_ztna_profile_internet_steering_exclusions.test", "exclusion.#", "3"),
					),
				},
			},
		})
	}, minWaitTime)
}

func TestAccZtnaProfileInternetSteeringDestinationLists_withExclusions(t *testing.T) {
	rateLimitedTest(t, func() {
		profileName := fmt.Sprintf("tfAccDlEx%s", acctest.RandStringFromCharSet(6, acctest.CharSetAlphaNum))
		dlName := fmt.Sprintf("tfAcc-dle-%s", acctest.RandStringFromCharSet(6, acctest.CharSetAlphaNum))

		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { testAccPreCheck(t) },
			ProtoV6ProviderFactories: testAccCiscoSecureAccessProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: testAccZtnaProfileDestListWithExclusionsConfig(profileName, dlName),
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttr("ciscosecureaccess_ztna_profile_internet_steering_destination_lists.test", "destination_list.#", "1"),
						resource.TestCheckResourceAttr("ciscosecureaccess_ztna_profile_internet_steering_destination_lists.test", "destination_list.0.exclusions.#", "2"),
					),
				},
			},
		})
	}, minWaitTime)
}

func TestAccZtnaPrivateSteeringDestination_update(t *testing.T) {
	rateLimitedTest(t, func() {
		profileName := fmt.Sprintf("tfAccPsdU%s", acctest.RandStringFromCharSet(6, acctest.CharSetAlphaNum))

		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { testAccPreCheck(t) },
			ProtoV6ProviderFactories: testAccCiscoSecureAccessProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: testAccZtnaPrivateSteeringDestUpdateStep1Config(profileName),
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttr("ciscosecureaccess_ztna_private_steering_destination.test", "endpoint", "*.update-psd.example.com"),
						resource.TestCheckResourceAttr("ciscosecureaccess_ztna_private_steering_destination.test", "exclusions.#", "1"),
					),
				},
				{
					Config: testAccZtnaPrivateSteeringDestUpdateStep2Config(profileName),
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttr("ciscosecureaccess_ztna_private_steering_destination.test", "endpoint", "*.update-psd.example.com"),
						resource.TestCheckResourceAttr("ciscosecureaccess_ztna_private_steering_destination.test", "exclusions.#", "2"),
					),
				},
			},
		})
	}, minWaitTime)
}

func TestAccZtnaPrivateSteeringDestination_ipEndpoint(t *testing.T) {
	rateLimitedTest(t, func() {
		profileName := fmt.Sprintf("tfAccPsdIp%s", acctest.RandStringFromCharSet(6, acctest.CharSetAlphaNum))

		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { testAccPreCheck(t) },
			ProtoV6ProviderFactories: testAccCiscoSecureAccessProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: testAccZtnaPrivateSteeringDestIPConfig(profileName),
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttrSet("ciscosecureaccess_ztna_private_steering_destination.test", "id"),
						resource.TestCheckResourceAttr("ciscosecureaccess_ztna_private_steering_destination.test", "endpoint", "192.168.100.0/24"),
					),
				},
			},
		})
	}, minWaitTime)
}

func TestAccZtnaTrustedNetwork_trustedServers(t *testing.T) {
	rateLimitedTest(t, func() {
		name := fmt.Sprintf("tfAccTnSrv%s", acctest.RandStringFromCharSet(6, acctest.CharSetAlphaNum))

		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { testAccPreCheck(t) },
			ProtoV6ProviderFactories: testAccCiscoSecureAccessProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: testAccZtnaTrustedNetworkTrustedServersConfig(name),
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttrSet(testZtnaTrustedNetworkResourceName, "id"),
						resource.TestCheckResourceAttr(testZtnaTrustedNetworkResourceName, "network_name", name),
					),
				},
			},
		})
	}, minWaitTime)
}

func testAccZtnaProfilePrivateResourceMappings1Config(profileName, prName1 string) string {
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

resource "ciscosecureaccess_private_resource" "test1" {
  name         = %[2]q
  access_types = ["client"]
  description  = "PR for mapping update test 1"
  client_reachable_addresses = ["10.99.1.1"]
  addresses = [{
    addresses        = ["10.99.1.1"]
    traffic_selector = [{ ports = "443", protocol = "http/https" }]
  }]
}

resource "ciscosecureaccess_ztna_profile_private_resource_mappings" "test" {
  profile_id           = ciscosecureaccess_ztna_profile.test.id
  private_resource_ids = [ciscosecureaccess_private_resource.test1.id]
}
`, profileName, prName1)
}

func testAccZtnaProfilePrivateResourceMappings2Config(profileName, prName1, prName2 string) string {
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

resource "ciscosecureaccess_private_resource" "test1" {
  name         = %[2]q
  access_types = ["client"]
  description  = "PR for mapping update test 1"
  client_reachable_addresses = ["10.99.1.1"]
  addresses = [{
    addresses        = ["10.99.1.1"]
    traffic_selector = [{ ports = "443", protocol = "http/https" }]
  }]
}

resource "ciscosecureaccess_private_resource" "test2" {
  name         = %[3]q
  access_types = ["client"]
  description  = "PR for mapping update test 2"
  client_reachable_addresses = ["10.99.2.1"]
  addresses = [{
    addresses        = ["10.99.2.1"]
    traffic_selector = [{ ports = "443", protocol = "http/https" }]
  }]
}

resource "ciscosecureaccess_ztna_profile_private_resource_mappings" "test" {
  profile_id           = ciscosecureaccess_ztna_profile.test.id
  private_resource_ids = [
    ciscosecureaccess_private_resource.test1.id,
    ciscosecureaccess_private_resource.test2.id,
  ]
}
`, profileName, prName1, prName2)
}

func testAccZtnaProfileExclusionsStep1Config(profileName string) string {
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
      destination = "*.initial-excl.example.com"
      description = "Initial exclusion"
    }
  ]
}
`, profileName)
}

func testAccZtnaProfileExclusionsStep2Config(profileName string) string {
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
      destination = "*.initial-excl.example.com"
      description = "Initial exclusion"
    },
    {
      destination = "*.added-excl.example.com"
      description = "Added exclusion"
    },
    {
      destination = "safe.third-excl.example.com"
      description = "Third exclusion"
    }
  ]
}
`, profileName)
}

func testAccZtnaProfileDestListWithExclusionsConfig(profileName, dlName string) string {
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
    exclusions = ["*.skip-this.example.com", "internal.bypass.local"]
  }]
}
`, profileName, dlName)
}

func testAccZtnaPrivateSteeringDestUpdateStep1Config(profileName string) string {
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
  endpoint   = "*.update-psd.example.com"
  exclusions = ["public.update-psd.example.com"]
}
`, profileName)
}

func testAccZtnaPrivateSteeringDestUpdateStep2Config(profileName string) string {
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
  endpoint   = "*.update-psd.example.com"
  exclusions = ["public.update-psd.example.com", "api.update-psd.example.com"]
}
`, profileName)
}

func testAccZtnaPrivateSteeringDestIPConfig(profileName string) string {
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
  endpoint   = "192.168.100.0/24"
  exclusions = []
}
`, profileName)
}

func testAccZtnaTrustedNetworkTrustedServersConfig(name string) string {
	return fmt.Sprintf(`
resource "ciscosecureaccess_ztna_trusted_network" "test" {
  network_name   = %[1]q
  interface_type = 0
  is_default     = false

  criteria = {
    dns_servers = [{
      server_ip = "10.0.0.1"
    }]
    trusted_servers = [{
      url              = "https://trust.scalex.local/probe"
      certificate_hash = "abc123def456"
    }]
  }
}
`, name)
}

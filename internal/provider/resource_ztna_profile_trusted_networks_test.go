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

func TestAccZtnaProfilePrivateSteeringTrustedNetworks_basic(t *testing.T) {
	rateLimitedTest(t, func() {
		profileName := fmt.Sprintf("tfAccPsTn%s", acctest.RandStringFromCharSet(6, acctest.CharSetAlphaNum))
		tnName := fmt.Sprintf("tfAccTn%s", acctest.RandStringFromCharSet(6, acctest.CharSetAlphaNum))

		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { testAccPreCheck(t) },
			ProtoV6ProviderFactories: testAccCiscoSecureAccessProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: testAccZtnaProfilePrivateSteeringTNDConfig(profileName, tnName),
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttr("ciscosecureaccess_ztna_profile_private_steering_trusted_networks.test", "trusted_network_ids.#", "1"),
					),
				},
			},
		})
	}, minWaitTime)
}

func TestAccZtnaProfilePrivateSteeringTrustedNetworks_update(t *testing.T) {
	rateLimitedTest(t, func() {
		profileName := fmt.Sprintf("tfAccPsTnU%s", acctest.RandStringFromCharSet(6, acctest.CharSetAlphaNum))
		tnName1 := fmt.Sprintf("tfAccTn1%s", acctest.RandStringFromCharSet(6, acctest.CharSetAlphaNum))
		tnName2 := fmt.Sprintf("tfAccTn2%s", acctest.RandStringFromCharSet(6, acctest.CharSetAlphaNum))

		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { testAccPreCheck(t) },
			ProtoV6ProviderFactories: testAccCiscoSecureAccessProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: testAccZtnaProfilePrivateSteeringTNDConfig(profileName, tnName1),
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttr("ciscosecureaccess_ztna_profile_private_steering_trusted_networks.test", "trusted_network_ids.#", "1"),
					),
				},
				{
					Config: testAccZtnaProfilePrivateSteeringTNDMultiConfig(profileName, tnName1, tnName2),
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttr("ciscosecureaccess_ztna_profile_private_steering_trusted_networks.test", "trusted_network_ids.#", "2"),
					),
				},
			},
		})
	}, minWaitTime)
}

func TestAccZtnaProfileInternetSteeringTrustedNetworks_basic(t *testing.T) {
	rateLimitedTest(t, func() {
		profileName := fmt.Sprintf("tfAccIsTn%s", acctest.RandStringFromCharSet(6, acctest.CharSetAlphaNum))
		tnName := fmt.Sprintf("tfAccTn%s", acctest.RandStringFromCharSet(6, acctest.CharSetAlphaNum))

		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { testAccPreCheck(t) },
			ProtoV6ProviderFactories: testAccCiscoSecureAccessProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: testAccZtnaProfileInternetSteeringTNDConfig(profileName, tnName),
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttr("ciscosecureaccess_ztna_profile_internet_steering_trusted_networks.test", "trusted_network_ids.#", "1"),
					),
				},
			},
		})
	}, minWaitTime)
}

func TestAccZtnaProfileInternetSteeringTrustedNetworks_update(t *testing.T) {
	rateLimitedTest(t, func() {
		profileName := fmt.Sprintf("tfAccIsTnU%s", acctest.RandStringFromCharSet(6, acctest.CharSetAlphaNum))
		tnName1 := fmt.Sprintf("tfAccTn1%s", acctest.RandStringFromCharSet(6, acctest.CharSetAlphaNum))
		tnName2 := fmt.Sprintf("tfAccTn2%s", acctest.RandStringFromCharSet(6, acctest.CharSetAlphaNum))

		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { testAccPreCheck(t) },
			ProtoV6ProviderFactories: testAccCiscoSecureAccessProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: testAccZtnaProfileInternetSteeringTNDConfig(profileName, tnName1),
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttr("ciscosecureaccess_ztna_profile_internet_steering_trusted_networks.test", "trusted_network_ids.#", "1"),
					),
				},
				{
					Config: testAccZtnaProfileInternetSteeringTNDMultiConfig(profileName, tnName1, tnName2),
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttr("ciscosecureaccess_ztna_profile_internet_steering_trusted_networks.test", "trusted_network_ids.#", "2"),
					),
				},
			},
		})
	}, minWaitTime)
}

func testAccZtnaProfilePrivateSteeringTNDConfig(profileName, tnName string) string {
	return fmt.Sprintf(`
resource "ciscosecureaccess_ztna_trusted_network" "test" {
  network_name   = %[2]q
  interface_type = 0
  is_default     = false

  criteria = {
    dns_servers = [{
      server_ip = "10.0.0.1"
    }]
    dns_domains = [{
      name = "tnd-ps.scalex.local"
    }]
  }
}

resource "ciscosecureaccess_ztna_profile" "test" {
  profile_name = %[1]q
  priority     = 1

  secure_private_access = {
    trusted_networks_enabled = true
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

resource "ciscosecureaccess_ztna_profile_private_steering_trusted_networks" "test" {
  profile_id         = ciscosecureaccess_ztna_profile.test.id
  trusted_network_ids = [ciscosecureaccess_ztna_trusted_network.test.id]
}
`, profileName, tnName)
}

func testAccZtnaProfilePrivateSteeringTNDMultiConfig(profileName, tnName1, tnName2 string) string {
	return fmt.Sprintf(`
resource "ciscosecureaccess_ztna_trusted_network" "test" {
  network_name   = %[2]q
  interface_type = 0
  is_default     = false

  criteria = {
    dns_servers = [{
      server_ip = "10.0.0.1"
    }]
    dns_domains = [{
      name = "tnd-ps.scalex.local"
    }]
  }
}

resource "ciscosecureaccess_ztna_trusted_network" "test2" {
  network_name   = %[3]q
  interface_type = 0
  is_default     = false

  criteria = {
    dns_servers = [{
      server_ip = "10.0.0.2"
    }]
    dns_domains = [{
      name = "tnd-ps2.scalex.local"
    }]
  }
}

resource "ciscosecureaccess_ztna_profile" "test" {
  profile_name = %[1]q
  priority     = 1

  secure_private_access = {
    trusted_networks_enabled = true
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

resource "ciscosecureaccess_ztna_profile_private_steering_trusted_networks" "test" {
  profile_id         = ciscosecureaccess_ztna_profile.test.id
  trusted_network_ids = [
    ciscosecureaccess_ztna_trusted_network.test.id,
    ciscosecureaccess_ztna_trusted_network.test2.id,
  ]
}
`, profileName, tnName1, tnName2)
}

func testAccZtnaProfileInternetSteeringTNDConfig(profileName, tnName string) string {
	return fmt.Sprintf(`
resource "ciscosecureaccess_ztna_trusted_network" "test" {
  network_name   = %[2]q
  interface_type = 0
  is_default     = false

  criteria = {
    dns_servers = [{
      server_ip = "10.0.0.1"
    }]
    dns_domains = [{
      name = "tnd-is.scalex.local"
    }]
  }
}

resource "ciscosecureaccess_ztna_profile" "test" {
  profile_name = %[1]q
  priority     = 1

  secure_private_access = {
    trusted_networks_enabled = false
    enforcement_pause = { enabled = false }
  }
  secure_internet_access = {
    steering_mode            = 1
    trusted_networks_enabled = true
    enforcement_pause = { enabled = false }
  }
  users_data  = { all_users_enabled = true }
  groups_data = { all_groups_enabled = true }
}

resource "ciscosecureaccess_ztna_profile_internet_steering_trusted_networks" "test" {
  profile_id         = ciscosecureaccess_ztna_profile.test.id
  trusted_network_ids = [ciscosecureaccess_ztna_trusted_network.test.id]
}
`, profileName, tnName)
}

func testAccZtnaProfileInternetSteeringTNDMultiConfig(profileName, tnName1, tnName2 string) string {
	return fmt.Sprintf(`
resource "ciscosecureaccess_ztna_trusted_network" "test" {
  network_name   = %[2]q
  interface_type = 0
  is_default     = false

  criteria = {
    dns_servers = [{
      server_ip = "10.0.0.1"
    }]
    dns_domains = [{
      name = "tnd-is.scalex.local"
    }]
  }
}

resource "ciscosecureaccess_ztna_trusted_network" "test2" {
  network_name   = %[3]q
  interface_type = 0
  is_default     = false

  criteria = {
    dns_servers = [{
      server_ip = "10.0.0.2"
    }]
    dns_domains = [{
      name = "tnd-is2.scalex.local"
    }]
  }
}

resource "ciscosecureaccess_ztna_profile" "test" {
  profile_name = %[1]q
  priority     = 1

  secure_private_access = {
    trusted_networks_enabled = false
    enforcement_pause = { enabled = false }
  }
  secure_internet_access = {
    steering_mode            = 1
    trusted_networks_enabled = true
    enforcement_pause = { enabled = false }
  }
  users_data  = { all_users_enabled = true }
  groups_data = { all_groups_enabled = true }
}

resource "ciscosecureaccess_ztna_profile_internet_steering_trusted_networks" "test" {
  profile_id         = ciscosecureaccess_ztna_profile.test.id
  trusted_network_ids = [
    ciscosecureaccess_ztna_trusted_network.test.id,
    ciscosecureaccess_ztna_trusted_network.test2.id,
  ]
}
`, profileName, tnName1, tnName2)
}

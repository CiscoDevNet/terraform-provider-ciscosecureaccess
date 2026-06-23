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

const testZtnaProfileResourceName = "ciscosecureaccess_ztna_profile.test"

func TestAccZtnaProfile_basic(t *testing.T) {
	rateLimitedTest(t, func() {
		name := fmt.Sprintf("tfAccZtna%s", acctest.RandStringFromCharSet(6, acctest.CharSetAlphaNum))

		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { testAccPreCheck(t) },
			ProtoV6ProviderFactories: testAccCiscoSecureAccessProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: testAccZtnaProfileBasicConfig(name),
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttrSet(testZtnaProfileResourceName, "id"),
						resource.TestCheckResourceAttr(testZtnaProfileResourceName, "profile_name", name),
						resource.TestCheckResourceAttr(testZtnaProfileResourceName, "priority", "1"),
						resource.TestCheckResourceAttrSet(testZtnaProfileResourceName, "rev"),
						resource.TestCheckResourceAttrSet(testZtnaProfileResourceName, "organization_id"),
					),
				},
			},
		})
	}, minWaitTime)
}

func TestAccZtnaProfile_update(t *testing.T) {
	rateLimitedTest(t, func() {
		name := fmt.Sprintf("tfAccZtna%s", acctest.RandStringFromCharSet(6, acctest.CharSetAlphaNum))
		updatedName := name + "-updated"

		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { testAccPreCheck(t) },
			ProtoV6ProviderFactories: testAccCiscoSecureAccessProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: testAccZtnaProfileBasicConfig(name),
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttr(testZtnaProfileResourceName, "profile_name", name),
					),
				},
				{
					Config: testAccZtnaProfileBasicConfig(updatedName),
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttr(testZtnaProfileResourceName, "profile_name", updatedName),
					),
				},
			},
		})
	}, minWaitTime)
}

func TestAccZtnaProfile_internetSteering(t *testing.T) {
	rateLimitedTest(t, func() {
		name := fmt.Sprintf("tfAccZtnaIs%s", acctest.RandStringFromCharSet(6, acctest.CharSetAlphaNum))

		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { testAccPreCheck(t) },
			ProtoV6ProviderFactories: testAccCiscoSecureAccessProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: testAccZtnaProfileInternetSteeringConfig(name),
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttr(testZtnaProfileResourceName, "secure_internet_access.steering_mode", "1"),
						resource.TestCheckResourceAttr(testZtnaProfileResourceName, "secure_internet_access.trusted_networks_enabled", "true"),
					),
				},
			},
		})
	}, minWaitTime)
}

func testAccZtnaProfileBasicConfig(name string) string {
	return fmt.Sprintf(`
resource "ciscosecureaccess_ztna_profile" "test" {
  profile_name = %[1]q
  priority     = 1

  secure_private_access = {
    trusted_networks_enabled = false
    enforcement_pause = {
      enabled = false
    }
  }

  secure_internet_access = {
    steering_mode            = 0
    trusted_networks_enabled = false
    enforcement_pause = {
      enabled = false
    }
  }

  users_data = {
    all_users_enabled = true
  }

  groups_data = {
    all_groups_enabled = true
  }
}
`, name)
}

func TestAccZtnaProfile_operatingSystems(t *testing.T) {
	rateLimitedTest(t, func() {
		name := fmt.Sprintf("tfAccZtnaOs%s", acctest.RandStringFromCharSet(6, acctest.CharSetAlphaNum))

		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { testAccPreCheck(t) },
			ProtoV6ProviderFactories: testAccCiscoSecureAccessProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: testAccZtnaProfileOperatingSystemsConfig(name),
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttr(testZtnaProfileResourceName, "operating_systems.win.enabled", "true"),
						resource.TestCheckResourceAttr(testZtnaProfileResourceName, "operating_systems.mac_intel.enabled", "true"),
						resource.TestCheckResourceAttr(testZtnaProfileResourceName, "operating_systems.linux_64.enabled", "false"),
						resource.TestCheckResourceAttr(testZtnaProfileResourceName, "operating_systems.apple_ios.enabled", "false"),
						resource.TestCheckResourceAttr(testZtnaProfileResourceName, "operating_systems.android.generic_android.enabled", "false"),
						resource.TestCheckResourceAttr(testZtnaProfileResourceName, "operating_systems.android.knox_android.enabled", "false"),
					),
				},
			},
		})
	}, minWaitTime)
}

func testAccZtnaProfileInternetSteeringConfig(name string) string {
	return fmt.Sprintf(`
resource "ciscosecureaccess_ztna_profile" "test" {
  profile_name = %[1]q
  priority     = 1

  secure_private_access = {
    trusted_networks_enabled = true
    enforcement_pause = {
      enabled = false
    }
  }

  secure_internet_access = {
    steering_mode            = 1
    trusted_networks_enabled = true
    enforcement_pause = {
      enabled = false
    }
  }

  users_data = {
    all_users_enabled = true
  }

  groups_data = {
    all_groups_enabled = true
  }
}
`, name)
}

func testAccZtnaProfileOperatingSystemsConfig(name string) string {
	return fmt.Sprintf(`
resource "ciscosecureaccess_ztna_profile" "test" {
  profile_name = %[1]q
  priority     = 1

  secure_private_access = {
    trusted_networks_enabled = false
    enforcement_pause = {
      enabled = false
    }
  }

  secure_internet_access = {
    steering_mode            = 0
    trusted_networks_enabled = false
    enforcement_pause = {
      enabled = false
    }
  }

  operating_systems = {
    mac_intel = {
      enabled = true
    }
    win = {
      enabled = true
    }
    linux_64 = {
      enabled = false
    }
    apple_ios = {
      enabled = false
    }
    android = {
      generic_android = {
        enabled = false
      }
      knox_android = {
        enabled = false
      }
    }
  }

  users_data = {
    all_users_enabled = true
  }

  groups_data = {
    all_groups_enabled = true
  }
}
`, name)
}

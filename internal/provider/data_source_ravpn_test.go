// Copyright 2025 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccRavpnHeadendsDataSource_basic(t *testing.T) {
	rateLimitedTest(t, func() {
		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { testAccPreCheck(t) },
			ProtoV6ProviderFactories: testAccCiscoSecureAccessProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: testAccRavpnHeadendsDataSourceConfig(),
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttr("data.ciscosecureaccess_ravpn_headends.test", "organization_id", "8376136"),
					),
				},
			},
		})
	}, minWaitTime)
}

func TestAccRavpnProfilesDataSource_basic(t *testing.T) {
	rateLimitedTest(t, func() {
		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { testAccPreCheck(t) },
			ProtoV6ProviderFactories: testAccCiscoSecureAccessProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: testAccRavpnProfilesDataSourceConfig(),
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttr("data.ciscosecureaccess_ravpn_profiles.test", "organization_id", "8376136"),
					),
				},
			},
		})
	}, minWaitTime)
}

func testAccRavpnHeadendsDataSourceConfig() string {
	return `
data "ciscosecureaccess_ravpn_headends" "test" {
  organization_id = "8376136"
}
`
}

func testAccRavpnProfilesDataSourceConfig() string {
	return `
data "ciscosecureaccess_ravpn_profiles" "test" {
  organization_id = "8376136"
}
`
}

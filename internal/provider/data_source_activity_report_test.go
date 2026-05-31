// Copyright 2025 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

const (
	testActivityReportDataSourceName = "data.ciscosecureaccess_activity_report.test"
)

func TestActivityReport_basic(t *testing.T) {
	rateLimitedTest(t, func() {
		from := "-1days"
		to := "now"

		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { testAccPreCheck(t) },
			ProtoV6ProviderFactories: testAccCiscoSecureAccessProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: testAccActivityReportBasicConfig(from, to),
					ConfigStateChecks: []statecheck.StateCheck{
						statecheck.ExpectKnownValue(
							testActivityReportDataSourceName,
							tfjsonpath.New("total_count"),
							knownvalue.NotNull(),
						),
					},
				},
			},
		})
	}, minWaitTime)
}

func testAccActivityReportBasicConfig(from, to string) string {
	return fmt.Sprintf(`
data "ciscosecureaccess_activity_report" "test" {
  from  = "%s"
  to    = "%s"
  limit = 5
}`, from, to)
}

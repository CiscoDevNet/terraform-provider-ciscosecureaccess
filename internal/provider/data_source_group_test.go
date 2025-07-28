// Copyright 2025 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/CiscoDevNet/go-ciscosecureaccess/reports"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

// Test constants for group data source tests
const (
	testGroupDataSourceName = "data.ciscosecureaccess_group.group"
	testGroupIdentityType   = "directory_group"
)

func TestGroupDataSource_basic(t *testing.T) {
	rateLimitedTest(t, func() {
		groupFixture, err := testGroupFixture(t)
		if err != nil {
			t.Fatalf("Failed to get group fixture: %v", err)
		}

		// Escape backslashes in group name for filter
		groupFilter := strings.ReplaceAll(groupFixture.Label, "\\", "\\\\")

		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { testAccPreCheck(t) },
			ProtoV6ProviderFactories: testAccCiscoSecureAccessProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: testAccGroupDataSourceConfig(groupFilter),
					ConfigStateChecks: []statecheck.StateCheck{
						statecheck.ExpectKnownValue(
							testGroupDataSourceName,
							tfjsonpath.New("groups").AtSliceIndex(0).AtMapKey("id"),
							knownvalue.Int64Exact(groupFixture.Id),
						),
					},
				},
			},
		})
	}, minWaitTime)
}

// testGroupFixture retrieves a sample group for testing
func testGroupFixture(t *testing.T) (*reports.Identity, error) {
	reportingClient := testClientFactory(t).GetReportsClient(context.Background())

	identities, httpResp, err := reportingClient.UtilityAPI.GetIdentities(context.Background()).
		Limit(1).
		Offset(0).
		Identitytypes(testGroupIdentityType).
		Execute()
	if err != nil {
		return nil, fmt.Errorf("failed to get identities: %w", err)
	}

	if httpResp.StatusCode != 200 {
		return nil, fmt.Errorf("unexpected HTTP status: %d - %s", httpResp.StatusCode, httpResp.Status)
	}

	if len(identities.Data) == 0 {
		return nil, fmt.Errorf("no groups returned from API")
	}

	return &identities.Data[0], nil
}

// testAccGroupDataSourceConfig returns a configuration for a group data source with the provided filter
func testAccGroupDataSourceConfig(filter string) string {
	// Remove "(deleted)" suffix if present and escape backslashes
	cleanFilter := strings.ReplaceAll(
		strings.ReplaceAll(filter, " (deleted)", ""),
		"\\", "\\\\",
	)

	return fmt.Sprintf(`
data "ciscosecureaccess_group" "group" {
  filter = "%s"
}`, cleanFilter)
}

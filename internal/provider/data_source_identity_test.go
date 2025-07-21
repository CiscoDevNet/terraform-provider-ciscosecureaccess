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

// Test constants for identity data source tests
const (
	testIdentityDataSourceName = "data.ciscosecureaccess_identity.identity"
)

func TestIdentityDataSource_basic(t *testing.T) {
	rateLimitedTest(t, func() {
		identityFixture, err := testIdentityFixture(t)
		if err != nil {
			t.Fatalf("Failed to get identity fixture: %v", err)
		}

		// Extract username from label format: "display name (username)"
		identityFilter := extractUsernameFromLabel(identityFixture.Label)

		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { testAccPreCheck(t) },
			ProtoV6ProviderFactories: testAccCiscoSecureAccessProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: testAccIdentityDataSourceConfig(identityFilter),
					ConfigStateChecks: []statecheck.StateCheck{
						statecheck.ExpectKnownValue(
							testIdentityDataSourceName,
							tfjsonpath.New("identities").AtSliceIndex(0).AtMapKey("id"),
							knownvalue.Int64Exact(identityFixture.Id),
						),
					},
				},
			},
		})
	}, minWaitTime)
}

// testIdentityFixture retrieves a sample identity for testing
func testIdentityFixture(t *testing.T) (*reports.Identity, error) {
	reportingClient := testClientFactory(t).GetReportsClient(context.Background())

	identities, httpResp, err := reportingClient.UtilityAPI.GetIdentities(context.Background()).
		Limit(1).
		Offset(0).
		Identitytypes(identityTypeUser).
		Execute()
	if err != nil {
		return nil, fmt.Errorf("failed to get identities: %w", err)
	}

	if httpResp.StatusCode != 200 {
		return nil, fmt.Errorf("unexpected HTTP status: %d - %s", httpResp.StatusCode, httpResp.Status)
	}

	if len(identities.Data) == 0 {
		return nil, fmt.Errorf("no identities returned from API")
	}

	return &identities.Data[0], nil
}

// extractUsernameFromLabel extracts username from label format: "display name (username)"
func extractUsernameFromLabel(label string) string {
	// Find the username within parentheses
	if startIdx := strings.Index(label, "("); startIdx != -1 {
		if endIdx := strings.Index(label[startIdx:], ")"); endIdx != -1 {
			return label[startIdx+1 : startIdx+endIdx]
		}
	}
	// Fallback to the full label if no parentheses found
	return label
}

// testAccIdentityDataSourceConfig returns a configuration for an identity data source with the provided filter
func testAccIdentityDataSourceConfig(filter string) string {
	return fmt.Sprintf(`
data "ciscosecureaccess_identity" "identity" {
  filter = "%s"
}`, filter)
}

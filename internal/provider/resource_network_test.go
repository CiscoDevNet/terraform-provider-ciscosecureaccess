// Copyright 2025 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/CiscoDevNet/go-ciscosecureaccess/client"
	"github.com/CiscoDevNet/go-ciscosecureaccess/networks"
	"github.com/hashicorp/terraform-plugin-sdk/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

func TestUpdateNetworkModelFromObject_AllFieldsSet(t *testing.T) {
	createdAt := time.Date(2025, 5, 23, 12, 34, 56, 0, time.UTC)
	obj := networks.NewNetworkObject(12345, "corporate-network", "10.0.0.0", 8, false, true, "OPEN", createdAt)

	model := &networkResourceModel{}
	updateNetworkModelFromObject(model, obj)

	if got := model.Id.ValueInt64(); got != 12345 {
		t.Errorf("Id: expected 12345, got %d", got)
	}
	if got := model.Name.ValueString(); got != "corporate-network" {
		t.Errorf("Name: expected %q, got %q", "corporate-network", got)
	}
	if got := model.IpAddress.ValueString(); got != "10.0.0.0" {
		t.Errorf("IpAddress: expected %q, got %q", "10.0.0.0", got)
	}
	if got := model.PrefixLength.ValueInt64(); got != 8 {
		t.Errorf("PrefixLength: expected 8, got %d", got)
	}
	if got := model.IsDynamic.ValueBool(); got != false {
		t.Errorf("IsDynamic: expected false, got %v", got)
	}
	if got := model.Status.ValueString(); got != "OPEN" {
		t.Errorf("Status: expected %q, got %q", "OPEN", got)
	}
	expectedCreatedAt := createdAt.Format("2006-01-02T15:04:05Z07:00")
	if got := model.CreatedAt.ValueString(); got != expectedCreatedAt {
		t.Errorf("CreatedAt: expected %q, got %q", expectedCreatedAt, got)
	}
}

func TestUpdateNetworkModelFromObject_StatusValues(t *testing.T) {
	tests := []struct {
		name      string
		status    string
		isDynamic bool
	}{
		{"open static", "OPEN", false},
		{"closed static", "CLOSED", false},
		{"open dynamic", "OPEN", true},
		{"closed dynamic", "CLOSED", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			obj := networks.NewNetworkObject(1, "n", "192.168.1.0", 24, tc.isDynamic, true, tc.status, time.Now())

			model := &networkResourceModel{}
			updateNetworkModelFromObject(model, obj)

			if got := model.Status.ValueString(); got != tc.status {
				t.Errorf("Status: expected %q, got %q", tc.status, got)
			}
			if got := model.IsDynamic.ValueBool(); got != tc.isDynamic {
				t.Errorf("IsDynamic: expected %v, got %v", tc.isDynamic, got)
			}
		})
	}
}

const (
	testNetworkResourceName  = "ciscosecureaccess_network.test_resource"
	testNetworkNamePrefix    = "tfacc"
	testNetworkIPAddress     = "198.51.100.0"
	testNetworkPrefixLength  = int64(24)
	testNetworkUpdatedSuffix = "updated"
)

func generateNetworkTestName(suffix string) string {
	return fmt.Sprintf("%s%s-%s", testNetworkNamePrefix, acctest.RandStringFromCharSet(8, acctest.CharSetAlphaNum), suffix)
}

func TestNetworkResource_basic(t *testing.T) {
	rateLimitedTest(t, func() {
		name := generateNetworkTestName("basic")

		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { testAccPreCheck(t) },
			ProtoV6ProviderFactories: testAccCiscoSecureAccessProviderFactories,
			CheckDestroy:             testAccCheckNetworkDestroy,
			Steps: []resource.TestStep{
				{
					Config: testAccNetworkBasicConfig(name),
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttrSet(testNetworkResourceName, "id"),
						resource.TestCheckResourceAttr(testNetworkResourceName, "name", name),
						resource.TestCheckResourceAttr(testNetworkResourceName, "ip_address", testNetworkIPAddress),
						resource.TestCheckResourceAttr(testNetworkResourceName, "status", "OPEN"),
					),
					ConfigStateChecks: []statecheck.StateCheck{
						statecheck.ExpectKnownValue(testNetworkResourceName, tfjsonpath.New("name"), knownvalue.StringExact(name)),
						statecheck.ExpectKnownValue(testNetworkResourceName, tfjsonpath.New("status"), knownvalue.StringExact("OPEN")),
					},
				},
				{
					ResourceName:      testNetworkResourceName,
					ImportState:       true,
					ImportStateVerify: true,
				},
			},
		})
	}, minWaitTime)
}

func TestNetworkResource_update(t *testing.T) {
	rateLimitedTest(t, func() {
		name := generateNetworkTestName("upd")
		updatedName := generateNetworkTestName(testNetworkUpdatedSuffix)

		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { testAccPreCheck(t) },
			ProtoV6ProviderFactories: testAccCiscoSecureAccessProviderFactories,
			CheckDestroy:             testAccCheckNetworkDestroy,
			Steps: []resource.TestStep{
				{
					Config: testAccNetworkBasicConfig(name),
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttrSet(testNetworkResourceName, "id"),
						resource.TestCheckResourceAttr(testNetworkResourceName, "name", name),
					),
				},
				{
					Config: testAccNetworkBasicConfig(updatedName),
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttrSet(testNetworkResourceName, "id"),
						resource.TestCheckResourceAttr(testNetworkResourceName, "name", updatedName),
					),
					ConfigStateChecks: []statecheck.StateCheck{
						statecheck.ExpectKnownValue(testNetworkResourceName, tfjsonpath.New("name"), knownvalue.StringExact(updatedName)),
					},
				},
			},
		})
	}, minWaitTime)
}

func testAccCheckNetworkDestroy(s *terraform.State) error {
	ctx := context.Background()
	factory := &client.SSEClientFactory{
		KeyId:     os.Getenv("CISCOSECUREACCESS_KEY_ID"),
		KeySecret: os.Getenv("CISCOSECUREACCESS_KEY_SECRET"),
	}
	c := factory.GetNetworksClient(ctx)
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "ciscosecureaccess_network" {
			continue
		}
		id := atoi64(rs.Primary.ID)
		_, httpRes, _ := c.NetworksAPI.GetNetwork(ctx, id).Execute()
		if httpRes == nil || httpRes.StatusCode != 404 {
			return fmt.Errorf("network %d still exists after destroy", id)
		}
	}
	return nil
}

func testAccNetworkBasicConfig(name string) string {
	return fmt.Sprintf(`
resource "ciscosecureaccess_network" "test_resource" {
  name          = %q
  ip_address    = %q
  prefix_length = %d
  is_dynamic    = false
  status        = "OPEN"
}
`, name, testNetworkIPAddress, testNetworkPrefixLength)
}

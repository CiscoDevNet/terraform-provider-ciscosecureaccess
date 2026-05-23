// Copyright 2025 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/CiscoDevNet/go-ciscosecureaccess/client"
	"github.com/CiscoDevNet/go-ciscosecureaccess/internalnetworks"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-sdk/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

func ptrInt64(v int64) *int64    { return &v }
func ptrString(v string) *string { return &v }

func TestFlattenInternalNetworkObject_SiteIdSet(t *testing.T) {
	network := &internalnetworks.InternalNetworkObject{
		OriginId:     42,
		Name:         "site-net",
		IpAddress:    "10.0.0.0",
		PrefixLength: 24,
		SiteId:       ptrInt64(101),
		SiteName:     ptrString("hq-site"),
	}
	model := &internalNetworkResourceModel{}
	flattenInternalNetworkObject(network, model)

	if model.Id.ValueInt64() != 42 {
		t.Errorf("Id = %d, want 42", model.Id.ValueInt64())
	}
	if model.Name.ValueString() != "site-net" {
		t.Errorf("Name = %q, want %q", model.Name.ValueString(), "site-net")
	}
	if model.IpAddress.ValueString() != "10.0.0.0" {
		t.Errorf("IpAddress = %q", model.IpAddress.ValueString())
	}
	if model.PrefixLength.ValueInt64() != 24 {
		t.Errorf("PrefixLength = %d", model.PrefixLength.ValueInt64())
	}
	if model.SiteId.ValueInt64() != 101 {
		t.Errorf("SiteId = %d, want 101", model.SiteId.ValueInt64())
	}
	if !model.NetworkId.IsNull() {
		t.Errorf("NetworkId should be null, got %v", model.NetworkId)
	}
	if !model.TunnelId.IsNull() {
		t.Errorf("TunnelId should be null, got %v", model.TunnelId)
	}
	if model.SiteName.ValueString() != "hq-site" {
		t.Errorf("SiteName = %q, want %q", model.SiteName.ValueString(), "hq-site")
	}
	if !model.NetworkName.IsNull() {
		t.Errorf("NetworkName should be null")
	}
	if !model.TunnelName.IsNull() {
		t.Errorf("TunnelName should be null")
	}
}

func TestFlattenInternalNetworkObject_NetworkIdSet(t *testing.T) {
	network := &internalnetworks.InternalNetworkObject{
		OriginId:     7,
		Name:         "net-net",
		IpAddress:    "172.16.0.0",
		PrefixLength: 16,
		NetworkId:    ptrInt64(202),
		NetworkName:  ptrString("branch-net"),
	}
	model := &internalNetworkResourceModel{}
	flattenInternalNetworkObject(network, model)

	if model.NetworkId.ValueInt64() != 202 {
		t.Errorf("NetworkId = %d, want 202", model.NetworkId.ValueInt64())
	}
	if !model.SiteId.IsNull() {
		t.Errorf("SiteId should be null")
	}
	if !model.TunnelId.IsNull() {
		t.Errorf("TunnelId should be null")
	}
	if model.NetworkName.ValueString() != "branch-net" {
		t.Errorf("NetworkName = %q", model.NetworkName.ValueString())
	}
	if !model.SiteName.IsNull() {
		t.Errorf("SiteName should be null")
	}
	if !model.TunnelName.IsNull() {
		t.Errorf("TunnelName should be null")
	}
}

func TestFlattenInternalNetworkObject_TunnelIdSet(t *testing.T) {
	network := &internalnetworks.InternalNetworkObject{
		OriginId:     99,
		Name:         "tun-net",
		IpAddress:    "192.168.0.0",
		PrefixLength: 24,
		TunnelId:     ptrInt64(303),
		TunnelName:   ptrString("ntg-1"),
	}
	model := &internalNetworkResourceModel{}
	flattenInternalNetworkObject(network, model)

	if model.TunnelId.ValueInt64() != 303 {
		t.Errorf("TunnelId = %d, want 303", model.TunnelId.ValueInt64())
	}
	if !model.SiteId.IsNull() {
		t.Errorf("SiteId should be null")
	}
	if !model.NetworkId.IsNull() {
		t.Errorf("NetworkId should be null")
	}
	if model.TunnelName.ValueString() != "ntg-1" {
		t.Errorf("TunnelName = %q", model.TunnelName.ValueString())
	}
	if !model.SiteName.IsNull() {
		t.Errorf("SiteName should be null")
	}
	if !model.NetworkName.IsNull() {
		t.Errorf("NetworkName should be null")
	}
}

func TestFlattenInternalNetworkObject_AllNamesAbsent(t *testing.T) {
	network := &internalnetworks.InternalNetworkObject{
		OriginId:     1,
		Name:         "bare",
		IpAddress:    "10.1.1.0",
		PrefixLength: 24,
		SiteId:       ptrInt64(1),
	}
	model := &internalNetworkResourceModel{
		SiteId:    types.Int64Unknown(),
		NetworkId: types.Int64Unknown(),
		TunnelId:  types.Int64Unknown(),
	}
	flattenInternalNetworkObject(network, model)

	if !model.SiteName.IsNull() {
		t.Errorf("SiteName should be null when absent")
	}
	if !model.NetworkName.IsNull() {
		t.Errorf("NetworkName should be null when absent")
	}
	if !model.TunnelName.IsNull() {
		t.Errorf("TunnelName should be null when absent")
	}
	if !model.NetworkId.IsNull() {
		t.Errorf("NetworkId should be null when unset in response and unknown in model")
	}
	if !model.TunnelId.IsNull() {
		t.Errorf("TunnelId should be null when unset in response and unknown in model")
	}
}

// Test constants for internal network resource tests
const (
	testInternalNetworkResourceName  = "ciscosecureaccess_internal_network.test_resource"
	testInternalNetworkNamePrefix    = "tfAcc"
	testInternalNetworkIPAddress     = "198.51.100.0"
	testInternalNetworkPrefixLength  = 24
	testInternalNetworkUpdatedSuffix = "updated"
)

// generateInternalNetworkTestName creates a unique test name for internal network tests
func generateInternalNetworkTestName(suffix string) string {
	return fmt.Sprintf("%s%s-%s", testInternalNetworkNamePrefix, acctest.RandStringFromCharSet(8, acctest.CharSetAlphaNum), suffix)
}

func TestInternalNetworkResource_basic(t *testing.T) {
	rateLimitedTest(t, func() {
		testName := generateInternalNetworkTestName("basic")

		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { testAccPreCheck(t) },
			ProtoV6ProviderFactories: testAccCiscoSecureAccessProviderFactories,
			CheckDestroy:             testAccCheckInternalNetworkDestroy,
			Steps: []resource.TestStep{
				{
					Config: testAccInternalNetworkBasicConfig(testName),
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttrSet(testInternalNetworkResourceName, "id"),
						resource.TestCheckResourceAttr(testInternalNetworkResourceName, "name", testName),
						resource.TestCheckResourceAttr(testInternalNetworkResourceName, "ip_address", testInternalNetworkIPAddress),
						resource.TestCheckResourceAttr(testInternalNetworkResourceName, "prefix_length", fmt.Sprintf("%d", testInternalNetworkPrefixLength)),
					),
					ConfigStateChecks: []statecheck.StateCheck{
						statecheck.ExpectKnownValue(testInternalNetworkResourceName, tfjsonpath.New("name"), knownvalue.StringExact(testName)),
						statecheck.ExpectKnownValue(testInternalNetworkResourceName, tfjsonpath.New("ip_address"), knownvalue.StringExact(testInternalNetworkIPAddress)),
						statecheck.ExpectKnownValue(testInternalNetworkResourceName, tfjsonpath.New("prefix_length"), knownvalue.Int64Exact(testInternalNetworkPrefixLength)),
					},
				},
			},
		})
	}, minWaitTime)
}

func TestInternalNetworkResource_update(t *testing.T) {
	rateLimitedTest(t, func() {
		testName := generateInternalNetworkTestName("update")
		updatedName := generateInternalNetworkTestName(testInternalNetworkUpdatedSuffix)

		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { testAccPreCheck(t) },
			ProtoV6ProviderFactories: testAccCiscoSecureAccessProviderFactories,
			CheckDestroy:             testAccCheckInternalNetworkDestroy,
			Steps: []resource.TestStep{
				{
					Config: testAccInternalNetworkBasicConfig(testName),
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttrSet(testInternalNetworkResourceName, "id"),
						resource.TestCheckResourceAttr(testInternalNetworkResourceName, "name", testName),
					),
				},
				{
					Config: testAccInternalNetworkBasicConfig(updatedName),
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttrSet(testInternalNetworkResourceName, "id"),
						resource.TestCheckResourceAttr(testInternalNetworkResourceName, "name", updatedName),
					),
					ConfigStateChecks: []statecheck.StateCheck{
						statecheck.ExpectKnownValue(testInternalNetworkResourceName, tfjsonpath.New("name"), knownvalue.StringExact(updatedName)),
					},
				},
			},
		})
	}, minWaitTime)
}

func testAccInternalNetworkBasicConfig(name string) string {
	return fmt.Sprintf(`
resource "ciscosecureaccess_site" "test_site" {
  name = %q
}

resource "ciscosecureaccess_internal_network" "test_resource" {
  name          = %q
  ip_address    = %q
  prefix_length = %d
  site_id       = ciscosecureaccess_site.test_site.id
}
`, name+"-site", name, testInternalNetworkIPAddress, testInternalNetworkPrefixLength)
}

func testAccCheckInternalNetworkDestroy(s *terraform.State) error {
	ctx := context.Background()
	factory := &client.SSEClientFactory{
		KeyId:     os.Getenv("CISCOSECUREACCESS_KEY_ID"),
		KeySecret: os.Getenv("CISCOSECUREACCESS_KEY_SECRET"),
	}
	c := factory.GetInternalNetworksClient(ctx)
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "ciscosecureaccess_internal_network" {
			continue
		}
		id := atoi64(rs.Primary.ID)
		_, httpRes, _ := c.InternalNetworksAPI.GetInternalNetwork(ctx, id).Execute()
		if httpRes == nil || httpRes.StatusCode != 404 {
			return fmt.Errorf("internal network %d still exists after destroy", id)
		}
	}
	return nil
}

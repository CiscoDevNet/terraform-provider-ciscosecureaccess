package provider

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

// Test constants for network tunnel group tests
const (
	testNTGResourceName     = "ciscosecureaccess_network_tunnel_group.test_resource"
	testNTGNamePrefix       = "tfAcc"
	testNTGRegion           = "us-test-2"
	testNTGIdentifierPrefix = "tfacctest"
	testNTGPresharedKey     = "TerraformTestkey1234567"
	testNTGDeviceType       = "other"
	testNTGNetworkCIDR      = "10.10.110.0/24"
	testNTGNetworkCIDR2     = "10.10.111.0/24"
	testNTGUpdatedCIDR      = "10.10.112.0/24"
)

// Common test helper functions

// generateNTGTestName creates a unique test name with the given suffix
func generateNTGTestName(suffix string) string {
	return fmt.Sprintf("%s%s %s", testNTGNamePrefix, acctest.RandStringFromCharSet(8, acctest.CharSetAlphaNum), suffix)
}

// generateNTGIdentifierPrefix creates a unique identifier prefix for testing
func generateNTGIdentifierPrefix(suffix string) string {
	return fmt.Sprintf("%s%s", testNTGIdentifierPrefix, acctest.RandStringFromCharSet(6, acctest.CharSetAlphaNum))
}

// commonNTGChecks returns the basic checks that should be performed for all NTG tests
func commonNTGChecks(resourceName, expectedName string) resource.TestCheckFunc {
	return resource.ComposeAggregateTestCheckFunc(
		resource.TestCheckResourceAttrSet(resourceName, "id"),
		resource.TestCheckResourceAttr(resourceName, "name", expectedName),
		resource.TestCheckResourceAttr(resourceName, "region", testNTGRegion),
		resource.TestCheckResourceAttr(resourceName, "device_type", testNTGDeviceType),
		resource.TestCheckResourceAttrSet(resourceName, "hubs.#"),
	)
}

// commonNTGStateChecks returns the common state checks for NTG resources
func commonNTGStateChecks(resourceName, expectedName, identifierPrefix string) []statecheck.StateCheck {
	return []statecheck.StateCheck{
		statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(expectedName)),
		statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("region"), knownvalue.StringExact(testNTGRegion)),
		statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("identifier_prefix"), knownvalue.StringExact(identifierPrefix)),
		statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("device_type"), knownvalue.StringExact(testNTGDeviceType)),
		statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("preshared_key"), knownvalue.StringExact(testNTGPresharedKey)),
	}
}

func TestNetworkTunnelGroup_basic(t *testing.T) {
	rateLimitedTest(t, func() {
		testName := generateNTGTestName("basic")
		identifierPrefix := generateNTGIdentifierPrefix("basic")

		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { testAccPreCheck(t) },
			ProtoV6ProviderFactories: testAccCiscoSecureAccessProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: testAccNTGBasicConfig(testName, identifierPrefix),
					Check:  commonNTGChecks(testNTGResourceName, testName),
					ConfigStateChecks: append(
						commonNTGStateChecks(testNTGResourceName, testName, identifierPrefix),
						statecheck.ExpectKnownValue(testNTGResourceName, tfjsonpath.New("network_cidrs"), knownvalue.SetExact([]knownvalue.Check{knownvalue.StringExact(testNTGNetworkCIDR)})),
					),
				},
			},
		})
	}, minWaitTime)
}

func TestNetworkTunnelGroup_multipleCIDRs(t *testing.T) {
	rateLimitedTest(t, func() {
		testName := generateNTGTestName("multi")
		identifierPrefix := generateNTGIdentifierPrefix("multi")

		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { testAccPreCheck(t) },
			ProtoV6ProviderFactories: testAccCiscoSecureAccessProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: testAccNTGMultipleCIDRsConfig(testName, identifierPrefix),
					Check:  commonNTGChecks(testNTGResourceName, testName),
					ConfigStateChecks: append(
						commonNTGStateChecks(testNTGResourceName, testName, identifierPrefix),
						statecheck.ExpectKnownValue(testNTGResourceName, tfjsonpath.New("network_cidrs"),
							knownvalue.SetExact([]knownvalue.Check{
								knownvalue.StringExact(testNTGNetworkCIDR),
								knownvalue.StringExact(testNTGNetworkCIDR2),
							})),
					),
				},
			},
		})
	}, minWaitTime)
}

// TestNetworkTunnelGroup_update tests update operations on NTG resources
func TestNetworkTunnelGroup_update(t *testing.T) {
	rateLimitedTest(t, func() {
		testName := generateNTGTestName("update")
		updatedTestName := testName + "d"
		identifierPrefix := generateNTGIdentifierPrefix("update")

		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { testAccPreCheck(t) },
			ProtoV6ProviderFactories: testAccCiscoSecureAccessProviderFactories,
			Steps: []resource.TestStep{
				{
					// Create initial resource
					Config: testAccNTGBasicConfig(testName, identifierPrefix),
					Check:  commonNTGChecks(testNTGResourceName, testName),
					ConfigStateChecks: append(
						commonNTGStateChecks(testNTGResourceName, testName, identifierPrefix),
						statecheck.ExpectKnownValue(testNTGResourceName, tfjsonpath.New("network_cidrs"), knownvalue.SetExact([]knownvalue.Check{knownvalue.StringExact(testNTGNetworkCIDR)})),
					),
				},
				{
					// Update the resource name
					Config: testAccNTGBasicConfig(updatedTestName, identifierPrefix),
					Check:  commonNTGChecks(testNTGResourceName, updatedTestName),
					ConfigStateChecks: append(
						commonNTGStateChecks(testNTGResourceName, updatedTestName, identifierPrefix),
						statecheck.ExpectKnownValue(testNTGResourceName, tfjsonpath.New("network_cidrs"), knownvalue.SetExact([]knownvalue.Check{knownvalue.StringExact(testNTGNetworkCIDR)})),
					),
				},
			},
		})
	}, minWaitTime)
}

// TestNetworkTunnelGroup_updateCIDRs tests updating network CIDRs
func TestNetworkTunnelGroup_updateCIDRs(t *testing.T) {
	rateLimitedTest(t, func() {
		testName := generateNTGTestName("cidrUpdate")
		identifierPrefix := generateNTGIdentifierPrefix("cidrupd")

		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { testAccPreCheck(t) },
			ProtoV6ProviderFactories: testAccCiscoSecureAccessProviderFactories,
			Steps: []resource.TestStep{
				{
					// Create initial resource with single CIDR
					Config: testAccNTGBasicConfig(testName, identifierPrefix),
					Check:  commonNTGChecks(testNTGResourceName, testName),
					ConfigStateChecks: append(
						commonNTGStateChecks(testNTGResourceName, testName, identifierPrefix),
						statecheck.ExpectKnownValue(testNTGResourceName, tfjsonpath.New("network_cidrs"), knownvalue.SetExact([]knownvalue.Check{knownvalue.StringExact(testNTGNetworkCIDR)})),
					),
				},
				{
					// Update to multiple CIDRs
					Config: testAccNTGMultipleCIDRsConfig(testName, identifierPrefix),
					Check:  commonNTGChecks(testNTGResourceName, testName),
					ConfigStateChecks: append(
						commonNTGStateChecks(testNTGResourceName, testName, identifierPrefix),
						statecheck.ExpectKnownValue(testNTGResourceName, tfjsonpath.New("network_cidrs"),
							knownvalue.SetExact([]knownvalue.Check{
								knownvalue.StringExact(testNTGNetworkCIDR),
								knownvalue.StringExact(testNTGNetworkCIDR2),
							})),
					),
				},
				{
					// Update to different CIDR
					Config: testAccNTGUpdatedCIDRConfig(testName, identifierPrefix),
					Check:  commonNTGChecks(testNTGResourceName, testName),
					ConfigStateChecks: append(
						commonNTGStateChecks(testNTGResourceName, testName, identifierPrefix),
						statecheck.ExpectKnownValue(testNTGResourceName, tfjsonpath.New("network_cidrs"), knownvalue.SetExact([]knownvalue.Check{knownvalue.StringExact(testNTGUpdatedCIDR)})),
					),
				},
			},
		})
	}, minWaitTime)
}

// TestNetworkTunnelGroup_updatePresharedKey tests updating preshared key
func TestNetworkTunnelGroup_updatePresharedKey(t *testing.T) {
	rateLimitedTest(t, func() {
		testName := generateNTGTestName("pskUpdate")
		identifierPrefix := generateNTGIdentifierPrefix("pskupd")
		updatedPresharedKey := testNTGPresharedKey + "X"

		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { testAccPreCheck(t) },
			ProtoV6ProviderFactories: testAccCiscoSecureAccessProviderFactories,
			Steps: []resource.TestStep{
				{
					// Create initial resource
					Config: testAccNTGBasicConfig(testName, identifierPrefix),
					Check:  commonNTGChecks(testNTGResourceName, testName),
					ConfigStateChecks: append(
						commonNTGStateChecks(testNTGResourceName, testName, identifierPrefix),
						statecheck.ExpectKnownValue(testNTGResourceName, tfjsonpath.New("network_cidrs"), knownvalue.SetExact([]knownvalue.Check{knownvalue.StringExact(testNTGNetworkCIDR)})),
					),
				},
				{
					// Update preshared key
					Config: testAccNTGCustomPresharedKeyConfig(testName, identifierPrefix, updatedPresharedKey),
					Check:  commonNTGChecks(testNTGResourceName, testName),
					ConfigStateChecks: []statecheck.StateCheck{
						statecheck.ExpectKnownValue(testNTGResourceName, tfjsonpath.New("name"), knownvalue.StringExact(testName)),
						statecheck.ExpectKnownValue(testNTGResourceName, tfjsonpath.New("region"), knownvalue.StringExact(testNTGRegion)),
						statecheck.ExpectKnownValue(testNTGResourceName, tfjsonpath.New("identifier_prefix"), knownvalue.StringExact(identifierPrefix)),
						statecheck.ExpectKnownValue(testNTGResourceName, tfjsonpath.New("device_type"), knownvalue.StringExact(testNTGDeviceType)),
						statecheck.ExpectKnownValue(testNTGResourceName, tfjsonpath.New("preshared_key"), knownvalue.StringExact(updatedPresharedKey)),
						statecheck.ExpectKnownValue(testNTGResourceName, tfjsonpath.New("network_cidrs"), knownvalue.SetExact([]knownvalue.Check{knownvalue.StringExact(testNTGNetworkCIDR)})),
					},
				},
			},
		})
	}, minWaitTime)
}

// Configuration generators for different test scenarios

// testAccNTGBasicConfig returns a basic NTG configuration with single CIDR
func testAccNTGBasicConfig(name, identifierPrefix string) string {
	return fmt.Sprintf(`
resource "ciscosecureaccess_network_tunnel_group" "test_resource" {
    name              = "%s"
    network_cidrs     = ["%s"]
    region            = "%s"
    identifier_prefix = "%s"
    preshared_key     = "%s"
    device_type       = "%s"
}`, name, testNTGNetworkCIDR, testNTGRegion, identifierPrefix, testNTGPresharedKey, testNTGDeviceType)
}

// testAccNTGMultipleCIDRsConfig returns an NTG configuration with multiple CIDRs
func testAccNTGMultipleCIDRsConfig(name, identifierPrefix string) string {
	return fmt.Sprintf(`
resource "ciscosecureaccess_network_tunnel_group" "test_resource" {
    name              = "%s"
    network_cidrs     = ["%s", "%s"]
    region            = "%s"
    identifier_prefix = "%s"
    preshared_key     = "%s"
    device_type       = "%s"
}`, name, testNTGNetworkCIDR, testNTGNetworkCIDR2, testNTGRegion, identifierPrefix, testNTGPresharedKey, testNTGDeviceType)
}

// testAccNTGUpdatedCIDRConfig returns an NTG configuration with updated CIDR
func testAccNTGUpdatedCIDRConfig(name, identifierPrefix string) string {
	return fmt.Sprintf(`
resource "ciscosecureaccess_network_tunnel_group" "test_resource" {
    name              = "%s"
    network_cidrs     = ["%s"]
    region            = "%s"
    identifier_prefix = "%s"
    preshared_key     = "%s"
    device_type       = "%s"
}`, name, testNTGUpdatedCIDR, testNTGRegion, identifierPrefix, testNTGPresharedKey, testNTGDeviceType)
}

// testAccNTGCustomPresharedKeyConfig returns an NTG configuration with custom preshared key
func testAccNTGCustomPresharedKeyConfig(name, identifierPrefix, presharedKey string) string {
	return fmt.Sprintf(`
resource "ciscosecureaccess_network_tunnel_group" "test_resource" {
    name              = "%s"
    network_cidrs     = ["%s"]
    region            = "%s"
    identifier_prefix = "%s"
    preshared_key     = "%s"
    device_type       = "%s"
}`, name, testNTGNetworkCIDR, testNTGRegion, identifierPrefix, presharedKey, testNTGDeviceType)
}

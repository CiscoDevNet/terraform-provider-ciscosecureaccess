// Copyright 2025 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

// Test constants for resource connector agent tests
const (
	// Test configuration constants
	testConnectorAgentNamePrefix = "tfAcc"
	testConnectorAgentHostname   = "test-connector-host"

	// Resource identifiers
	testConnectorAgentResourceName = "ciscosecureaccess_resource_connector_agent.test_agent"
)

func TestResourceConnectorAgentResource_instanceID(t *testing.T) {
	if os.Getenv("TEST_CISCOSECUREACCESS_CONNECTOR_AGENT_INSTANCE_ID") == "" {
		t.Skip("Skipping test for connector agent instance ID as environment variable TEST_CISCOSECUREACCESS_CONNECTOR_AGENT_INSTANCE_ID")
	}
	rName := os.Getenv("TEST_CISCOSECUREACCESS_CONNECTOR_AGENT_INSTANCE_ID") // Ensure the environment variable is set for instance ID tests
	rateLimitedTest(t, func() {

		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { testAccPreCheck(t) },
			ProtoV6ProviderFactories: testAccCiscoSecureAccessProviderFactories,
			//CheckDestroy:             testAccCheckResourceConnectorAgentDestroy,
			Steps: []resource.TestStep{
				{
					Config: testAccResourceConnectorAgentConfigInstanceID(rName, rName),
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttrSet(testConnectorAgentResourceName, "id"),
						resource.TestCheckResourceAttr(testConnectorAgentResourceName, "instance_id", rName),
						resource.TestCheckResourceAttrSet(testConnectorAgentResourceName, "status"),
					),
					ConfigStateChecks: buildConnectorAgentInstanceIDStateChecks(rName),
				},
			},
		})
	}, minWaitTime)
}

func TestResourceConnectorAgentResource_hostname(t *testing.T) {
	if os.Getenv("TEST_CISCOSSE_CONNECTOR_AGENT_INSTANCE_ID") == "" {
		t.Skip("Skipping test for connector agent instance ID as environment variable TEST_CISCOSSE_CONNECTOR_AGENT_INSTANCE_ID")
	}
	rName := os.Getenv("TEST_CISCOSSE_CONNECTOR_AGENT_INSTANCE_ID") // Ensure the environment variable is set for instance ID tests
	rateLimitedTest(t, func() {

		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { testAccPreCheck(t) },
			ProtoV6ProviderFactories: testAccCiscoSecureAccessProviderFactories,
			//CheckDestroy:             testAccCheckResourceConnectorAgentDestroy,
			Steps: []resource.TestStep{
				{
					Config: testAccResourceConnectorAgentConfigHostname(rName, rName),
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttrSet(testConnectorAgentResourceName, "id"),
						resource.TestCheckResourceAttr(testConnectorAgentResourceName, "hostname", rName),
						resource.TestCheckResourceAttrSet(testConnectorAgentResourceName, "status"),
					),
					ConfigStateChecks: buildConnectorAgentHostnameStateChecks(rName),
				},
			},
		})
	}, minWaitTime)
}

func TestResourceConnectorAgentResource_enabled(t *testing.T) {
	if os.Getenv("TEST_CISCOSSE_CONNECTOR_AGENT_INSTANCE_ID") == "" {
		t.Skip("Skipping test for connector agent enabled as environment variable TEST_CISCOSSE_CONNECTOR_AGENT_INSTANCE_ID")
	}
	rName := os.Getenv("TEST_CISCOSSE_CONNECTOR_AGENT_INSTANCE_ID") // Ensure the environment variable is set for instance ID tests

	rateLimitedTest(t, func() {
		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { testAccPreCheck(t) },
			ProtoV6ProviderFactories: testAccCiscoSecureAccessProviderFactories,
			//CheckDestroy:             testAccCheckResourceConnectorAgentDestroy,
			Steps: []resource.TestStep{
				{
					Config: testAccResourceConnectorAgentConfigEnabled(rName, rName, true),
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttrSet(testConnectorAgentResourceName, "id"),
						resource.TestCheckResourceAttr(testConnectorAgentResourceName, "instance_id", rName),
						resource.TestCheckResourceAttr(testConnectorAgentResourceName, "enabled", "true"),
					),
				},
				{
					Config: testAccResourceConnectorAgentConfigEnabled(rName, rName, false),
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttrSet(testConnectorAgentResourceName, "id"),
						resource.TestCheckResourceAttr(testConnectorAgentResourceName, "instance_id", rName),
						resource.TestCheckResourceAttr(testConnectorAgentResourceName, "enabled", "false"),
					),
				},
			},
		})
	}, 30*time.Second)
}

// buildConnectorAgentInstanceIDStateChecks returns state checks for instance ID-based configuration
func buildConnectorAgentInstanceIDStateChecks(instanceID string) []statecheck.StateCheck {
	return []statecheck.StateCheck{
		statecheck.ExpectKnownValue(testConnectorAgentResourceName, tfjsonpath.New("instance_id"),
			knownvalue.StringExact(instanceID)),
		statecheck.ExpectKnownValue(testConnectorAgentResourceName, tfjsonpath.New("id"),
			knownvalue.NotNull()),
		statecheck.ExpectKnownValue(testConnectorAgentResourceName, tfjsonpath.New("status"),
			knownvalue.NotNull()),
	}
}

// buildConnectorAgentHostnameStateChecks returns state checks for hostname-based configuration
func buildConnectorAgentHostnameStateChecks(hostname string) []statecheck.StateCheck {
	return []statecheck.StateCheck{
		statecheck.ExpectKnownValue(testConnectorAgentResourceName, tfjsonpath.New("hostname"),
			knownvalue.StringExact(hostname)),
		statecheck.ExpectKnownValue(testConnectorAgentResourceName, tfjsonpath.New("id"),
			knownvalue.NotNull()),
		statecheck.ExpectKnownValue(testConnectorAgentResourceName, tfjsonpath.New("status"),
			knownvalue.NotNull()),
	}
}

// testAccResourceConnectorAgentConfigInstanceID generates Terraform configuration for instance ID-based tests
func testAccResourceConnectorAgentConfigInstanceID(name, instanceID string) string {
	return fmt.Sprintf(`
resource "ciscosecureaccess_resource_connector_agent" "test_agent" {
  instance_id = "%s"
}`, instanceID)
}

// testAccResourceConnectorAgentConfigHostname generates Terraform configuration for hostname-based tests
func testAccResourceConnectorAgentConfigHostname(name, hostname string) string {
	return fmt.Sprintf(`
resource "ciscosecureaccess_resource_connector_agent" "test_agent" {
  hostname = "%s"
}`, hostname)
}

// testAccResourceConnectorAgentConfigEnabled generates Terraform configuration for enabled/disabled tests
func testAccResourceConnectorAgentConfigEnabled(name, instanceID string, enabled bool) string {
	return fmt.Sprintf(`
resource "ciscosecureaccess_resource_connector_agent" "test_agent" {
  instance_id = "%s"
  enabled     = %t
}`, instanceID, enabled)
}

// testAccResourceConnectorAgentConfigConfirmed generates Terraform configuration for confirmation tests
func testAccResourceConnectorAgentConfigConfirmed(name, instanceID string, confirmed bool) string {
	return fmt.Sprintf(`
resource "ciscosecureaccess_resource_connector_agent" "test_agent" {
  instance_id = "%s"
  confirmed   = %t
}`, instanceID, confirmed)
}

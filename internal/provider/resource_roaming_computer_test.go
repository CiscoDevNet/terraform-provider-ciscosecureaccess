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
	"github.com/CiscoDevNet/go-ciscosecureaccess/roaming"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

func TestSetRoamingComputerState_AllFieldsPopulated(t *testing.T) {
	lastSync := time.Date(2025, 5, 23, 14, 30, 45, 0, time.UTC)

	computer := &roaming.RoamingComputerObject{}
	computer.SetOriginId(123456)
	computer.SetDeviceId("abc123def456")
	computer.SetName("laptop-corp-001")
	computer.SetType("roaming")
	computer.SetStatus("Active")
	computer.SetSwgStatus("On")
	computer.SetLastSync(lastSync)
	computer.SetVersion("5.1.2.0")
	computer.SetOsVersion("14.5.0")
	computer.SetOsVersionName("macOS Sonoma")

	state := &roamingComputerResourceModel{}
	setRoamingComputerState(state, computer)

	if got := state.OriginId.ValueInt64(); got != 123456 {
		t.Errorf("OriginId = %d, want 123456", got)
	}
	if got := state.DeviceId.ValueString(); got != "abc123def456" {
		t.Errorf("DeviceId = %q, want %q", got, "abc123def456")
	}
	if got := state.Name.ValueString(); got != "laptop-corp-001" {
		t.Errorf("Name = %q, want %q", got, "laptop-corp-001")
	}
	if got := state.Type.ValueString(); got != "roaming" {
		t.Errorf("Type = %q, want %q", got, "roaming")
	}
	if got := state.Status.ValueString(); got != "Active" {
		t.Errorf("Status = %q, want %q", got, "Active")
	}
	if got := state.SwgStatus.ValueString(); got != "On" {
		t.Errorf("SwgStatus = %q, want %q", got, "On")
	}
	if got := state.Version.ValueString(); got != "5.1.2.0" {
		t.Errorf("Version = %q, want %q", got, "5.1.2.0")
	}
	if got := state.OsVersion.ValueString(); got != "14.5.0" {
		t.Errorf("OsVersion = %q, want %q", got, "14.5.0")
	}
	if got := state.OsVersionName.ValueString(); got != "macOS Sonoma" {
		t.Errorf("OsVersionName = %q, want %q", got, "macOS Sonoma")
	}
}

func TestSetRoamingComputerState_LastSyncFormatting(t *testing.T) {
	tests := []struct {
		name     string
		lastSync time.Time
		want     string
	}{
		{
			name:     "UTC time",
			lastSync: time.Date(2025, 5, 23, 14, 30, 45, 0, time.UTC),
			want:     "2025-05-23T14:30:45Z",
		},
		{
			name:     "non-UTC offset",
			lastSync: time.Date(2025, 1, 2, 3, 4, 5, 0, time.FixedZone("EST", -5*3600)),
			want:     "2025-01-02T03:04:05-05:00",
		},
		{
			name:     "zero time",
			lastSync: time.Time{},
			want:     "0001-01-01T00:00:00Z",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			computer := &roaming.RoamingComputerObject{}
			computer.SetLastSync(tc.lastSync)

			state := &roamingComputerResourceModel{}
			setRoamingComputerState(state, computer)

			if got := state.LastSync.ValueString(); got != tc.want {
				t.Errorf("LastSync = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestSetRoamingComputerState_EmptyDefaults(t *testing.T) {
	computer := &roaming.RoamingComputerObject{}

	state := &roamingComputerResourceModel{}
	setRoamingComputerState(state, computer)

	if got := state.OriginId.ValueInt64(); got != 0 {
		t.Errorf("OriginId = %d, want 0", got)
	}
	if got := state.DeviceId.ValueString(); got != "" {
		t.Errorf("DeviceId = %q, want empty", got)
	}
	if got := state.Name.ValueString(); got != "" {
		t.Errorf("Name = %q, want empty", got)
	}
	if state.LastSync.IsNull() || state.LastSync.IsUnknown() {
		t.Errorf("LastSync should be a populated string value, got null/unknown")
	}
}

const testRoamingComputerResourceName = "ciscosecureaccess_roaming_computer.test_resource"

func TestRoamingComputerResource_importAndUpdate(t *testing.T) {
	deviceId := os.Getenv("CISCOSECUREACCESS_TEST_ROAMING_DEVICE_ID")
	if deviceId == "" {
		t.Skip("CISCOSECUREACCESS_TEST_ROAMING_DEVICE_ID not set, skipping acceptance test")
	}
	updatedName := "tfacc-roaming-updated"

	rateLimitedTest(t, func() {
		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { testAccPreCheck(t) },
			ProtoV6ProviderFactories: testAccCiscoSecureAccessProviderFactories,
			CheckDestroy:             testAccCheckRoamingComputerDestroy,
			Steps: []resource.TestStep{
				{
					ResourceName:      testRoamingComputerResourceName,
					ImportState:       true,
					ImportStateId:     deviceId,
					ImportStateVerify: false,
				},
				{
					Config: testAccRoamingComputerConfig(deviceId, updatedName),
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttr(testRoamingComputerResourceName, "device_id", deviceId),
						resource.TestCheckResourceAttr(testRoamingComputerResourceName, "name", updatedName),
					),
				},
			},
		})
	}, minWaitTime)
}

func testAccCheckRoamingComputerDestroy(s *terraform.State) error {
	ctx := context.Background()
	factory := &client.SSEClientFactory{
		KeyId:     os.Getenv("CISCOSECUREACCESS_KEY_ID"),
		KeySecret: os.Getenv("CISCOSECUREACCESS_KEY_SECRET"),
	}
	c := factory.GetRoamingClient(ctx)
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "ciscosecureaccess_roaming_computer" {
			continue
		}
		deviceId := rs.Primary.Attributes["device_id"]
		_, httpRes, _ := c.RoamingComputersAPI.GetRoamingComputer(ctx, deviceId).Execute()
		if httpRes == nil || httpRes.StatusCode != 404 {
			return fmt.Errorf("roaming computer %s still exists after destroy", deviceId)
		}
	}
	return nil
}

func testAccRoamingComputerConfig(deviceId, name string) string {
	return fmt.Sprintf(`
resource "ciscosecureaccess_roaming_computer" "test_resource" {
  device_id = %q
  name      = %q
}
`, deviceId, name)
}

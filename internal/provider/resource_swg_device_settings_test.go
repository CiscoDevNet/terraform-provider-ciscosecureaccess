// Copyright 2025 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"testing"

	"github.com/CiscoDevNet/go-ciscosecureaccess/client"
	"github.com/CiscoDevNet/go-ciscosecureaccess/swg"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

func newSWGInner(originID int64, value string) swg.ListSWGDeviceSettingsInner {
	return *swg.NewListSWGDeviceSettingsInner(originID, "device", swg.Value(value), "2025-01-01T00:00:00Z")
}

func TestCountSWGDeviceSettings(t *testing.T) {
	tests := []struct {
		name          string
		originIds     []int64
		settings      []swg.ListSWGDeviceSettingsInner
		expectedValue string
		wantSuccess   int64
		wantFail      int64
	}{
		{
			name:          "all devices match expected value",
			originIds:     []int64{1, 2, 3},
			settings:      []swg.ListSWGDeviceSettingsInner{newSWGInner(1, "1"), newSWGInner(2, "1"), newSWGInner(3, "1")},
			expectedValue: "1",
			wantSuccess:   3,
			wantFail:      0,
		},
		{
			name:          "no devices match expected value",
			originIds:     []int64{1, 2, 3},
			settings:      []swg.ListSWGDeviceSettingsInner{newSWGInner(1, "0"), newSWGInner(2, "0"), newSWGInner(3, "0")},
			expectedValue: "1",
			wantSuccess:   0,
			wantFail:      3,
		},
		{
			name:          "partial match",
			originIds:     []int64{1, 2, 3, 4},
			settings:      []swg.ListSWGDeviceSettingsInner{newSWGInner(1, "1"), newSWGInner(2, "0"), newSWGInner(3, "1"), newSWGInner(4, "0")},
			expectedValue: "1",
			wantSuccess:   2,
			wantFail:      2,
		},
		{
			name:          "origin id not returned by API is counted as fail",
			originIds:     []int64{1, 2, 3},
			settings:      []swg.ListSWGDeviceSettingsInner{newSWGInner(1, "1"), newSWGInner(2, "1")},
			expectedValue: "1",
			wantSuccess:   2,
			wantFail:      1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotSuccess, gotFail := countSWGDeviceSettings(tc.originIds, tc.settings, tc.expectedValue)
			if gotSuccess != tc.wantSuccess {
				t.Errorf("successCount: got %d, want %d", gotSuccess, tc.wantSuccess)
			}
			if gotFail != tc.wantFail {
				t.Errorf("failCount: got %d, want %d", gotFail, tc.wantFail)
			}
		})
	}
}

func TestOriginIdsFromList(t *testing.T) {
	ctx := context.Background()

	t.Run("valid list returns correct int64 slice", func(t *testing.T) {
		list := types.ListValueMust(types.Int64Type, []attr.Value{
			types.Int64Value(1),
			types.Int64Value(2),
			types.Int64Value(3),
		})
		errCalled := false
		ids := originIdsFromList(ctx, list, func(string, string) { errCalled = true })
		if errCalled {
			t.Fatalf("unexpected error callback invocation")
		}
		want := []int64{1, 2, 3}
		if len(ids) != len(want) {
			t.Fatalf("got %v, want %v", ids, want)
		}
		for i := range want {
			if ids[i] != want[i] {
				t.Errorf("index %d: got %d, want %d", i, ids[i], want[i])
			}
		}
	})

	t.Run("empty list returns empty slice without error", func(t *testing.T) {
		list := types.ListValueMust(types.Int64Type, []attr.Value{})
		errCalled := false
		ids := originIdsFromList(ctx, list, func(string, string) { errCalled = true })
		if errCalled {
			t.Fatalf("unexpected error callback invocation")
		}
		if len(ids) != 0 {
			t.Errorf("expected empty slice, got %v", ids)
		}
	})
}

const testSWGDeviceSettingsResourceName = "ciscosecureaccess_swg_device_settings.test_resource"

func TestSWGDeviceSettingsResource_basic(t *testing.T) {
	originIdStr := os.Getenv("CISCOSECUREACCESS_TEST_SWG_ORIGIN_ID")
	if originIdStr == "" {
		t.Skip("CISCOSECUREACCESS_TEST_SWG_ORIGIN_ID not set, skipping acceptance test")
	}
	originId, err := strconv.ParseInt(originIdStr, 10, 64)
	if err != nil {
		t.Fatalf("CISCOSECUREACCESS_TEST_SWG_ORIGIN_ID must be a valid integer: %v", err)
	}

	rateLimitedTest(t, func() {
		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { testAccPreCheck(t) },
			ProtoV6ProviderFactories: testAccCiscoSecureAccessProviderFactories,
			CheckDestroy:             testAccCheckSWGDeviceSettingsDestroy,
			Steps: []resource.TestStep{
				{
					Config: testAccSWGDeviceSettingsConfig(originId, "1"),
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttr(testSWGDeviceSettingsResourceName, "value", "1"),
					),
					ConfigStateChecks: []statecheck.StateCheck{
						statecheck.ExpectKnownValue(testSWGDeviceSettingsResourceName, tfjsonpath.New("value"), knownvalue.StringExact("1")),
					},
				},
				{
					Config: testAccSWGDeviceSettingsConfig(originId, "0"),
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttr(testSWGDeviceSettingsResourceName, "value", "0"),
					),
					ConfigStateChecks: []statecheck.StateCheck{
						statecheck.ExpectKnownValue(testSWGDeviceSettingsResourceName, tfjsonpath.New("value"), knownvalue.StringExact("0")),
					},
				},
			},
		})
	}, minWaitTime)
}

func testAccCheckSWGDeviceSettingsDestroy(s *terraform.State) error {
	ctx := context.Background()
	factory := &client.SSEClientFactory{
		KeyId:     os.Getenv("CISCOSECUREACCESS_KEY_ID"),
		KeySecret: os.Getenv("CISCOSECUREACCESS_KEY_SECRET"),
	}
	c := factory.GetSwgClient(ctx)
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "ciscosecureaccess_swg_device_settings" {
			continue
		}
		countStr := rs.Primary.Attributes["origin_ids.#"]
		count, err := strconv.Atoi(countStr)
		if err != nil || count == 0 {
			continue
		}
		var originIds []int64
		for i := 0; i < count; i++ {
			key := fmt.Sprintf("origin_ids.%d", i)
			id, err := strconv.ParseInt(rs.Primary.Attributes[key], 10, 64)
			if err == nil {
				originIds = append(originIds, id)
			}
		}
		if len(originIds) == 0 {
			continue
		}
		listReq := *swg.NewListSecureWebGatewayDeviceSettingsRequest(originIds)
		resp, httpRes, _ := c.SWGDeviceSettingsAPI.ListSecureWebGatewayDeviceSettings(ctx).ListSecureWebGatewayDeviceSettingsRequest(listReq).Execute()
		if (httpRes == nil || httpRes.StatusCode != 404) && len(resp) > 0 {
			return fmt.Errorf("SWG device settings for origin IDs %v still exist after destroy", originIds)
		}
	}
	return nil
}

func testAccSWGDeviceSettingsConfig(originId int64, value string) string {
	return fmt.Sprintf(`
resource "ciscosecureaccess_swg_device_settings" "test_resource" {
  origin_ids = [%d]
  value      = %q
}
`, originId, value)
}

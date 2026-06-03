// Copyright 2025 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/CiscoDevNet/go-ciscosecureaccess/client"
	"github.com/CiscoDevNet/go-ciscosecureaccess/swg"
)

var (
	_ resource.Resource                = &swgDeviceSettingsResource{}
	_ resource.ResourceWithConfigure   = &swgDeviceSettingsResource{}
	_ resource.ResourceWithImportState = &swgDeviceSettingsResource{}
)

func NewSWGDeviceSettingsResource() resource.Resource {
	return &swgDeviceSettingsResource{}
}

type swgDeviceSettingsResource struct {
	client swg.APIClient
}

type swgDeviceSettingsResourceModel struct {
	OriginIds    types.List   `tfsdk:"origin_ids"`
	Value        types.String `tfsdk:"value"`
	SuccessCount types.Int64  `tfsdk:"success_count"`
	FailCount    types.Int64  `tfsdk:"fail_count"`
}

func (r *swgDeviceSettingsResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_swg_device_settings"
}

func (r *swgDeviceSettingsResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	factory, ok := req.ProviderData.(*client.SSEClientFactory)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Resource Configure Type",
			fmt.Sprintf("Expected *client.SSEClientFactory, got: %T", req.ProviderData),
		)
		return
	}
	r.client = *factory.GetSwgClient(ctx)
}

func (r *swgDeviceSettingsResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Version:             0,
		Description:         "Manages Cisco Secure Access Secure Web Gateway device settings for a batch of origin IDs.",
		MarkdownDescription: "Manages Cisco Secure Access Secure Web Gateway device settings for a batch of origin IDs.",
		Attributes: map[string]schema.Attribute{
			"origin_ids": schema.ListAttribute{
				Description:         "Origin IDs of devices to apply Secure Web Gateway settings to. The list can contain 1-100 origin IDs.",
				MarkdownDescription: "Origin IDs of devices to apply Secure Web Gateway settings to. The list can contain 1-100 origin IDs.",
				Required:            true,
				ElementType:         types.Int64Type,
				Validators: []validator.List{
					listvalidator.SizeAtMost(100),
				},
			},
			"value": schema.StringAttribute{
				Description:         "Secure Web Gateway device setting value. Valid values are '0' (disabled) or '1' (enabled).",
				MarkdownDescription: "Secure Web Gateway device setting value. Valid values are `'0'` (disabled) or `'1'` (enabled).",
				Required:            true,
			},
			"success_count": schema.Int64Attribute{
				Description:         "Number of devices that successfully changed the Secure Web Gateway device setting.",
				MarkdownDescription: "Number of devices that successfully changed the Secure Web Gateway device setting.",
				Computed:            true,
				PlanModifiers:       []planmodifier.Int64{int64planmodifier.UseStateForUnknown()},
			},
			"fail_count": schema.Int64Attribute{
				Description:         "Number of devices that failed to change the Secure Web Gateway device setting.",
				MarkdownDescription: "Number of devices that failed to change the Secure Web Gateway device setting.",
				Computed:            true,
				PlanModifiers:       []planmodifier.Int64{int64planmodifier.UseStateForUnknown()},
			},
		},
	}
}

func (r *swgDeviceSettingsResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resp.Diagnostics.AddError(
		"Import Not Supported",
		"ciscosecureaccess_swg_device_settings does not support import. The resource manages batch device settings and has no single stable identifier.",
	)
}

func (r *swgDeviceSettingsResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	tflog.Info(ctx, "Creating SWG Device Settings")

	var plan swgDeviceSettingsResourceModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if planRep, err := json.Marshal(plan); err == nil {
		tflog.Debug(ctx, "Local SWG device settings definition", map[string]interface{}{"definition": string(planRep)})
	}

	originIds := originIdsFromList(ctx, plan.OriginIds, resp.Diagnostics.AddError)
	if resp.Diagnostics.HasError() {
		return
	}

	value, err := swg.NewValueFromValue(plan.Value.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Error parsing SWG device setting value", "Unexpected error: "+err.Error())
		return
	}

	createRequest := *swg.NewCreateSecureWebGatewayDeviceSettingsRequest(originIds, *value)
	createResp, _, err := r.client.SWGDeviceSettingsAPI.CreateSecureWebGatewayDeviceSettings(ctx).CreateSecureWebGatewayDeviceSettingsRequest(createRequest).Execute()
	if err != nil {
		resp.Diagnostics.AddError(
			"Error creating SWG device settings",
			fmt.Sprintf("Failed to create SWG device settings for origin IDs %s: %v", formatSWGOriginIds(originIds), err),
		)
		return
	}

	plan.SuccessCount = types.Int64Value(createResp.GetSuccessCount())
	plan.FailCount = types.Int64Value(createResp.GetFailCount())
	plan.Value = types.StringValue(string(createResp.GetValue()))

	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *swgDeviceSettingsResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state swgDeviceSettingsResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	originIds := originIdsFromList(ctx, state.OriginIds, resp.Diagnostics.AddError)
	if resp.Diagnostics.HasError() {
		return
	}
	tflog.Debug(ctx, "Reading SWG device settings", map[string]interface{}{"origin_ids": originIds})

	listRequest := *swg.NewListSecureWebGatewayDeviceSettingsRequest(originIds)
	readResp, httpRes, err := r.client.SWGDeviceSettingsAPI.ListSecureWebGatewayDeviceSettings(ctx).ListSecureWebGatewayDeviceSettingsRequest(listRequest).Execute()
	if httpRes != nil && httpRes.StatusCode == 404 {
		tflog.Info(ctx, "SWG device settings not found, removing from state", map[string]interface{}{"origin_ids": originIds})
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError(
			"Error reading SWG device settings",
			fmt.Sprintf("Could not read SWG device settings for origin IDs %s: %s", formatSWGOriginIds(originIds), err.Error()),
		)
		return
	}
	if httpRes == nil {
		resp.Diagnostics.AddError(
			"HTTP Response Error",
			fmt.Sprintf("Received nil HTTP response while reading SWG device settings for origin IDs %s", formatSWGOriginIds(originIds)),
		)
		return
	}

	if len(readResp) == 0 {
		tflog.Info(ctx, "SWG device settings returned no devices, removing from state", map[string]interface{}{"origin_ids": originIds})
		resp.State.RemoveResource(ctx)
		return
	}

	successCount, failCount := countSWGDeviceSettings(originIds, readResp, state.Value.ValueString())
	state.SuccessCount = types.Int64Value(successCount)
	state.FailCount = types.Int64Value(failCount)

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *swgDeviceSettingsResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	tflog.Info(ctx, "Updating SWG Device Settings")

	var plan, state swgDeviceSettingsResourceModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	diags = req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	originIds := originIdsFromList(ctx, plan.OriginIds, resp.Diagnostics.AddError)
	if resp.Diagnostics.HasError() {
		return
	}

	value, err := swg.NewValueFromValue(plan.Value.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Error parsing SWG device setting value", "Unexpected error: "+err.Error())
		return
	}

	createRequest := *swg.NewCreateSecureWebGatewayDeviceSettingsRequest(originIds, *value)
	updateResp, _, err := r.client.SWGDeviceSettingsAPI.CreateSecureWebGatewayDeviceSettings(ctx).CreateSecureWebGatewayDeviceSettingsRequest(createRequest).Execute()
	if err != nil {
		resp.Diagnostics.AddError(
			"Error updating SWG device settings",
			fmt.Sprintf("Could not update SWG device settings for origin IDs %s: %s", formatSWGOriginIds(originIds), err.Error()),
		)
		return
	}

	state.OriginIds, diags = types.ListValueFrom(ctx, types.Int64Type, originIds)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	state.Value = types.StringValue(string(updateResp.GetValue()))
	state.SuccessCount = types.Int64Value(updateResp.GetSuccessCount())
	state.FailCount = types.Int64Value(updateResp.GetFailCount())

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *swgDeviceSettingsResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state swgDeviceSettingsResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	originIds := originIdsFromList(ctx, state.OriginIds, resp.Diagnostics.AddError)
	if resp.Diagnostics.HasError() {
		return
	}
	tflog.Info(ctx, "Deleting SWG device settings", map[string]interface{}{"origin_ids": originIds})

	deleteRequest := *swg.NewListSecureWebGatewayDeviceSettingsRequest(originIds)
	_, httpRes, err := r.client.SWGDeviceSettingsAPI.DeleteSecureWebGatewayDeviceSettings(ctx).ListSecureWebGatewayDeviceSettingsRequest(deleteRequest).Execute()
	if httpRes != nil && httpRes.StatusCode == 404 {
		tflog.Info(ctx, "SWG device settings already deleted", map[string]interface{}{"origin_ids": originIds})
		return
	}
	if err != nil {
		resp.Diagnostics.AddError(
			"Error deleting SWG device settings",
			fmt.Sprintf("Could not delete SWG device settings for origin IDs %s: %s", formatSWGOriginIds(originIds), err.Error()),
		)
		return
	}

	tflog.Info(ctx, "Successfully deleted SWG device settings", map[string]interface{}{"origin_ids": originIds})
}

func originIdsFromList(ctx context.Context, list types.List, addError func(string, string)) []int64 {
	var ids []int64
	diags := list.ElementsAs(ctx, &ids, false)
	if diags.HasError() {
		addError("Error processing origin IDs", "Could not convert origin IDs")
		return nil
	}
	return ids
}

func countSWGDeviceSettings(originIds []int64, settings []swg.ListSWGDeviceSettingsInner, expectedValue string) (int64, int64) {
	settingsByOriginId := make(map[int64]swg.ListSWGDeviceSettingsInner, len(settings))
	for _, setting := range settings {
		settingsByOriginId[setting.GetOriginId()] = setting
	}

	var successCount, failCount int64
	for _, originId := range originIds {
		setting, found := settingsByOriginId[originId]
		if found && string(setting.GetValue()) == expectedValue {
			successCount++
		} else {
			failCount++
		}
	}
	return successCount, failCount
}

func formatSWGOriginIds(originIds []int64) string {
	values := make([]string, len(originIds))
	for i, originId := range originIds {
		values[i] = fmt.Sprintf("%d", originId)
	}
	return strings.Join(values, ",")
}

// Copyright 2025 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"

	"github.com/CiscoDevNet/go-ciscosecureaccess/client"
	"github.com/CiscoDevNet/go-ciscosecureaccess/rules"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/boolplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var _ resource.Resource = (*globalSettingsResource)(nil)
var _ resource.ResourceWithConfigure = &globalSettingsResource{}

// Constants for global settings resource
const (
	// Static ID for the global settings singleton resource
	globalSettingsResourceID = "global-settings"
)

// NewGlobalSettingsResource creates a new global settings resource
func NewGlobalSettingsResource() resource.Resource {
	return &globalSettingsResource{}
}

// globalSettingsResource manages global Secure Access settings
type globalSettingsResource struct {
	client rules.APIClient
}

// globalSettingsResourceModel represents the Terraform resource data model
type globalSettingsResourceModel struct {
	Id                     types.String `tfsdk:"id"`
	EnableGlobalDecryption types.Bool   `tfsdk:"enable_global_decryption"`
	GlobalIPSProfileId     types.Int64  `tfsdk:"global_ips_profile_id"`
}

// Configure adds the provider configured client to the resource
func (r *globalSettingsResource) Configure(ctx context.Context, req resource.ConfigureRequest, _ *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	r.client = *req.ProviderData.(*client.SSEClientFactory).GetRulesClient(ctx)
	tflog.Debug(ctx, "Configured global settings resource client")
}

// Metadata sets the resource type name
func (r *globalSettingsResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_global_settings"
}

// Schema defines the resource schema
func (r *globalSettingsResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manage global default rule settings for Cisco Secure Access",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "Unique identifier for the global settings resource",
				Computed:    true,
			},
			"enable_global_decryption": schema.BoolAttribute{
				Description:   "Enable IPS decryption in the global default rules",
				Optional:      true,
				Computed:      true,
				PlanModifiers: []planmodifier.Bool{boolplanmodifier.UseStateForUnknown()},
			},
			"global_ips_profile_id": schema.Int64Attribute{
				Description:   "IPS profile ID applied as part of global default rules",
				Optional:      true,
				Computed:      true,
				PlanModifiers: []planmodifier.Int64{int64planmodifier.UseStateForUnknown()},
			},
		},
	}
}

// Create creates the global settings resource
func (r *globalSettingsResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan globalSettingsResourceModel

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "Creating global settings resource", map[string]interface{}{
		"enable_global_decryption": plan.EnableGlobalDecryption.ValueBool(),
		"global_ips_profile_id":    plan.GlobalIPSProfileId.ValueInt64(),
	})

	// Fetch current state from API
	var currentState globalSettingsResourceModel
	diags := r.FetchState(ctx, &currentState)
	if diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}

	// Apply the planned changes
	diags = r.PutState(ctx, &currentState, &plan)
	if diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}

	// Set the static ID for this singleton resource
	plan.Id = types.StringValue(globalSettingsResourceID)

	tflog.Debug(ctx, "Successfully created global settings resource")

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// FetchState retrieves the current global settings state from the API
func (r *globalSettingsResource) FetchState(ctx context.Context, state *globalSettingsResourceModel) diag.Diagnostics {
	var diags diag.Diagnostics

	tflog.Debug(ctx, "Fetching global settings state from API")

	getResp, httpResp, err := r.client.RuleSettingsAndDefaultsAPI.GetPolicySettings(ctx).Execute()
	if err != nil {
		diags.AddError(
			"Error retrieving global policy settings",
			fmt.Sprintf("Error when calling RuleSettingsAndDefaultsAPI.GetPolicySettings: %v\nHTTP response: %v", err, httpResp),
		)
		return diags
	}

	tflog.Debug(ctx, "Successfully retrieved policy settings", map[string]interface{}{
		"settings_count": len(getResp),
	})

	// Parse the settings response
	for _, setting := range getResp {
		switch setting.SettingName {
		case rules.SETTINGNAME_SSE_GLOBAL_IPS_ENABLED:
			if setting.SettingValue.Bool != nil {
				state.EnableGlobalDecryption = types.BoolValue(*setting.SettingValue.Bool)
				tflog.Debug(ctx, "Found global IPS enabled setting", map[string]interface{}{
					"value": *setting.SettingValue.Bool,
				})
			}
		case rules.SETTINGNAME_UMBRELLA_POSTURE_IPS_PROFILE_ID:
			if setting.SettingValue.Int64 != nil {
				state.GlobalIPSProfileId = types.Int64Value(*setting.SettingValue.Int64)
				tflog.Debug(ctx, "Found global IPS profile ID setting", map[string]interface{}{
					"value": *setting.SettingValue.Int64,
				})
			}
		}
	}

	return diags
}

// PutState updates the global settings state via the API
func (r *globalSettingsResource) PutState(ctx context.Context, currentState *globalSettingsResourceModel, plan *globalSettingsResourceModel) diag.Diagnostics {
	var diags diag.Diagnostics

	// Update global decryption setting if it has changed
	if !plan.EnableGlobalDecryption.IsUnknown() && plan.EnableGlobalDecryption.ValueBool() != currentState.EnableGlobalDecryption.ValueBool() {
		tflog.Debug(ctx, "Updating global decryption setting", map[string]interface{}{
			"old_value": currentState.EnableGlobalDecryption.ValueBool(),
			"new_value": plan.EnableGlobalDecryption.ValueBool(),
		})

		settingsRequestObject := *rules.NewSettingsRequestObject()
		settingValue := plan.EnableGlobalDecryption.ValueBool()
		settingsRequestObject.SetSettingValue(rules.SettingValue{Bool: &settingValue})
		settingsRequestObject.SetSettingName(rules.SETTINGNAME_SSE_GLOBAL_IPS_ENABLED)

		_, httpResp, err := r.client.RuleSettingsAndDefaultsAPI.PutPolicySetting(ctx, string(rules.SETTINGNAME_SSE_GLOBAL_IPS_ENABLED)).SettingsRequestObject(settingsRequestObject).Execute()
		if err != nil {
			diags.AddError(
				"Error updating global decryption setting",
				fmt.Sprintf("Error when calling RuleSettingsAndDefaultsAPI.PutPolicySetting: %v\nHTTP response: %v", err, httpResp),
			)
			return diags
		}

		currentState.EnableGlobalDecryption = plan.EnableGlobalDecryption
		tflog.Debug(ctx, "Successfully updated global decryption setting")
	} else if plan.EnableGlobalDecryption.IsUnknown() {
		// If the plan value is unknown, use the current state value
		plan.EnableGlobalDecryption = currentState.EnableGlobalDecryption
	}

	// Update global IPS profile ID setting if it has changed
	if !plan.GlobalIPSProfileId.IsUnknown() && plan.GlobalIPSProfileId.ValueInt64() != currentState.GlobalIPSProfileId.ValueInt64() {
		tflog.Debug(ctx, "Updating global IPS profile ID setting", map[string]interface{}{
			"old_value": currentState.GlobalIPSProfileId.ValueInt64(),
			"new_value": plan.GlobalIPSProfileId.ValueInt64(),
		})

		settingsRequestObject := *rules.NewSettingsRequestObject()
		settingValue := plan.GlobalIPSProfileId.ValueInt64()
		settingsRequestObject.SetSettingName(rules.SETTINGNAME_UMBRELLA_POSTURE_IPS_PROFILE_ID)
		settingsRequestObject.SetSettingValue(rules.SettingValue{Int64: &settingValue})

		_, httpResp, err := r.client.RuleSettingsAndDefaultsAPI.PutPolicySetting(ctx, string(rules.SETTINGNAME_UMBRELLA_POSTURE_IPS_PROFILE_ID)).SettingsRequestObject(settingsRequestObject).Execute()
		if err != nil {
			diags.AddError(
				"Error updating global IPS profile ID setting",
				fmt.Sprintf("Error when calling RuleSettingsAndDefaultsAPI.PutPolicySetting: %v\nHTTP response: %v", err, httpResp),
			)
			return diags
		}

		currentState.GlobalIPSProfileId = plan.GlobalIPSProfileId
		tflog.Debug(ctx, "Successfully updated global IPS profile ID setting")
	} else if plan.GlobalIPSProfileId.IsUnknown() {
		// If the plan value is unknown, use the current state value
		plan.GlobalIPSProfileId = currentState.GlobalIPSProfileId
	}

	return diags
}

// Read reads the global settings resource state
func (r *globalSettingsResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data globalSettingsResourceModel

	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "Reading global settings resource state")

	// Read API call logic
	diags := r.FetchState(ctx, &data)
	if diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}

	// Set the static ID for this singleton resource
	data.Id = types.StringValue(globalSettingsResourceID)

	tflog.Debug(ctx, "Successfully read global settings resource state", map[string]interface{}{
		"enable_global_decryption": data.EnableGlobalDecryption.ValueBool(),
		"global_ips_profile_id":    data.GlobalIPSProfileId.ValueInt64(),
	})

	// Save updated data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// Update updates the global settings resource
func (r *globalSettingsResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state globalSettingsResourceModel

	// Read Terraform plan and state data into the models
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "Updating global settings resource", map[string]interface{}{
		"plan_enable_global_decryption":  plan.EnableGlobalDecryption.ValueBool(),
		"plan_global_ips_profile_id":     plan.GlobalIPSProfileId.ValueInt64(),
		"state_enable_global_decryption": state.EnableGlobalDecryption.ValueBool(),
		"state_global_ips_profile_id":    state.GlobalIPSProfileId.ValueInt64(),
	})

	// Update API call logic
	diags := r.PutState(ctx, &state, &plan)
	if diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}

	// Set the static ID for this singleton resource
	plan.Id = types.StringValue(globalSettingsResourceID)

	tflog.Debug(ctx, "Successfully updated global settings resource")

	// Save updated data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Delete removes the global settings resource from Terraform state
// Note: This doesn't actually delete the settings from the API since they are global
func (r *globalSettingsResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data globalSettingsResourceModel

	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "Deleting global settings resource from Terraform state", map[string]interface{}{
		"enable_global_decryption": data.EnableGlobalDecryption.ValueBool(),
		"global_ips_profile_id":    data.GlobalIPSProfileId.ValueInt64(),
	})

	// Note: Global settings are not actually deleted from the API
	// They remain configured as they were. This only removes the resource from Terraform state.

	tflog.Debug(ctx, "Successfully removed global settings resource from Terraform state")
}

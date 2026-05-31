// Copyright 2025 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/CiscoDevNet/go-ciscosecureaccess/client"
	"github.com/CiscoDevNet/go-ciscosecureaccess/roaming"
)

var (
	_ resource.Resource                = &roamingComputerResource{}
	_ resource.ResourceWithConfigure   = &roamingComputerResource{}
	_ resource.ResourceWithImportState = &roamingComputerResource{}
)

func NewRoamingComputerResource() resource.Resource {
	return &roamingComputerResource{}
}

type roamingComputerResource struct {
	client roaming.APIClient
}

type roamingComputerResourceModel struct {
	OriginId      types.Int64  `tfsdk:"origin_id"`
	DeviceId      types.String `tfsdk:"device_id"`
	Name          types.String `tfsdk:"name"`
	Type          types.String `tfsdk:"type"`
	Status        types.String `tfsdk:"status"`
	SwgStatus     types.String `tfsdk:"swg_status"`
	LastSync      types.String `tfsdk:"last_sync"`
	Version       types.String `tfsdk:"version"`
	OsVersion     types.String `tfsdk:"os_version"`
	OsVersionName types.String `tfsdk:"os_version_name"`
}

func (r *roamingComputerResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_roaming_computer"
}

func (r *roamingComputerResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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
	r.client = *factory.GetRoamingClient(ctx)
}

func (r *roamingComputerResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description:         "Manages a Cisco Secure Access Roaming Computer resource. Roaming computers are registered externally and must be imported into Terraform before they can be managed.",
		MarkdownDescription: "Manages a Cisco Secure Access Roaming Computer resource. Roaming computers are registered externally and must be imported into Terraform before they can be managed.",
		Version:             0,
		Attributes: map[string]schema.Attribute{
			"origin_id": schema.Int64Attribute{
				Description:         "Origin ID of the roaming computer.",
				MarkdownDescription: "Origin ID of the roaming computer.",
				Computed:            true,
				PlanModifiers:       []planmodifier.Int64{int64planmodifier.UseStateForUnknown()},
			},
			"device_id": schema.StringAttribute{
				Description:         "Hex device ID of the roaming computer. Used to import the resource.",
				MarkdownDescription: "Hex device ID of the roaming computer. Used to import the resource.",
				Computed:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"name": schema.StringAttribute{
				Description:         "Name of the roaming computer.",
				MarkdownDescription: "Name of the roaming computer.",
				Required:            true,
			},
			"type": schema.StringAttribute{
				Description:         "Type of the roaming computer.",
				MarkdownDescription: "Type of the roaming computer.",
				Computed:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"status": schema.StringAttribute{
				Description:         "Status of the roaming computer with DNS-layer security.",
				MarkdownDescription: "Status of the roaming computer with DNS-layer security.",
				Computed:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"swg_status": schema.StringAttribute{
				Description:         "Status of the roaming computer with Internet security (Secure Web Gateway).",
				MarkdownDescription: "Status of the roaming computer with Internet security (Secure Web Gateway).",
				Computed:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"last_sync": schema.StringAttribute{
				Description:         "RFC3339 timestamp of the last sync.",
				MarkdownDescription: "RFC3339 timestamp of the last sync.",
				Computed:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"version": schema.StringAttribute{
				Description:         "Version of the Cisco Secure Client with the Internet Security module deployed on the roaming computer.",
				MarkdownDescription: "Version of the Cisco Secure Client with the Internet Security module deployed on the roaming computer.",
				Computed:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"os_version": schema.StringAttribute{
				Description:         "OS version of the roaming computer.",
				MarkdownDescription: "OS version of the roaming computer.",
				Computed:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"os_version_name": schema.StringAttribute{
				Description:         "OS version name of the roaming computer.",
				MarkdownDescription: "OS version name of the roaming computer.",
				Computed:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
		},
	}
}

func (r *roamingComputerResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	tflog.Info(ctx, "Creating Roaming Computer is not supported")
	resp.Diagnostics.AddError(
		"Roaming Computer Creation Not Supported",
		"Cisco Secure Access roaming computers are registered externally and cannot be created by Terraform. Roaming computers must be imported using their device_id.",
	)
}

func (r *roamingComputerResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state roamingComputerResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	deviceId := state.DeviceId.ValueString()
	tflog.Debug(ctx, "Reading roaming computer", map[string]interface{}{"device_id": deviceId})

	readResp, httpRes, err := r.client.RoamingComputersAPI.GetRoamingComputer(ctx, deviceId).Execute()
	if httpRes != nil && httpRes.StatusCode == 404 {
		tflog.Info(ctx, "Roaming computer not found, removing from state", map[string]interface{}{"device_id": deviceId})
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError(
			"Error reading roaming computer",
			fmt.Sprintf("Could not read roaming computer device_id %s: %s", deviceId, err.Error()),
		)
		return
	}
	if readResp == nil {
		resp.Diagnostics.AddError(
			"Error reading roaming computer",
			fmt.Sprintf("Received nil response while reading roaming computer device_id %s", deviceId),
		)
		return
	}

	setRoamingComputerState(&state, readResp)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *roamingComputerResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	tflog.Info(ctx, "Updating Roaming Computer")

	var plan roamingComputerResourceModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	deviceId := plan.DeviceId.ValueString()
	updateRequest := *roaming.NewUpdateRoamingComputerRequest(plan.Name.ValueString())

	updateResp, _, err := r.client.RoamingComputersAPI.UpdateRoamingComputer(ctx, deviceId).UpdateRoamingComputerRequest(updateRequest).Execute()
	if err != nil {
		resp.Diagnostics.AddError(
			"Error updating roaming computer",
			fmt.Sprintf("Could not update roaming computer device_id %s: %s", deviceId, err.Error()),
		)
		return
	}
	if updateResp == nil {
		resp.Diagnostics.AddError(
			"Error updating roaming computer",
			fmt.Sprintf("Received nil response while updating roaming computer device_id %s", deviceId),
		)
		return
	}

	setRoamingComputerState(&plan, updateResp)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *roamingComputerResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state roamingComputerResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	deviceId := state.DeviceId.ValueString()
	tflog.Info(ctx, "Deleting roaming computer", map[string]interface{}{"device_id": deviceId})

	httpRes, err := r.client.RoamingComputersAPI.DeleteRoamingComputer(ctx, deviceId).Execute()
	if httpRes != nil && httpRes.StatusCode == 404 {
		tflog.Info(ctx, "Roaming computer already deleted", map[string]interface{}{"device_id": deviceId})
		return
	}
	if err != nil {
		resp.Diagnostics.AddError(
			"Error deleting roaming computer",
			fmt.Sprintf("Could not delete roaming computer device_id %s: %s", deviceId, err.Error()),
		)
		return
	}

	tflog.Info(ctx, "Successfully deleted roaming computer", map[string]interface{}{"device_id": deviceId})
}

func (r *roamingComputerResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("device_id"), req, resp)
}

func setRoamingComputerState(state *roamingComputerResourceModel, computer *roaming.RoamingComputerObject) {
	state.OriginId = types.Int64Value(computer.GetOriginId())
	state.DeviceId = types.StringValue(computer.GetDeviceId())
	state.Name = types.StringValue(computer.GetName())
	state.Type = types.StringValue(computer.GetType())
	state.Status = types.StringValue(computer.GetStatus())
	state.SwgStatus = types.StringValue(computer.GetSwgStatus())
	state.LastSync = types.StringValue(computer.GetLastSync().Format("2006-01-02T15:04:05Z07:00"))
	state.Version = types.StringValue(computer.GetVersion())
	state.OsVersion = types.StringValue(computer.GetOsVersion())
	state.OsVersionName = types.StringValue(computer.GetOsVersionName())
}

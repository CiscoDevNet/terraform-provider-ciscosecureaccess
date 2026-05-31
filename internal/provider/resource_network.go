// Copyright 2025 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/CiscoDevNet/go-ciscosecureaccess/client"
	"github.com/CiscoDevNet/go-ciscosecureaccess/networks"
)

var (
	_ resource.Resource                = &networkResource{}
	_ resource.ResourceWithConfigure   = &networkResource{}
	_ resource.ResourceWithImportState = &networkResource{}
)

func NewNetworkResource() resource.Resource {
	return &networkResource{}
}

type networkResource struct {
	client networks.APIClient
}

type networkResourceModel struct {
	Id           types.Int64  `tfsdk:"id"`
	Name         types.String `tfsdk:"name"`
	IpAddress    types.String `tfsdk:"ip_address"`
	PrefixLength types.Int64  `tfsdk:"prefix_length"`
	IsDynamic    types.Bool   `tfsdk:"is_dynamic"`
	Status       types.String `tfsdk:"status"`
	CreatedAt    types.String `tfsdk:"created_at"`
}

func (r *networkResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_network"
}

func (r *networkResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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
	r.client = *factory.GetNetworksClient(ctx)
}

func (r *networkResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Version:             0,
		Description:         "Manages a Cisco Secure Access Network resource.",
		MarkdownDescription: "Manages a Cisco Secure Access Network resource.",
		Attributes: map[string]schema.Attribute{
			"id": schema.Int64Attribute{
				Description:         "Unique origin ID of the network.",
				MarkdownDescription: "Unique origin ID of the network.",
				Computed:            true,
				PlanModifiers:       []planmodifier.Int64{int64planmodifier.UseStateForUnknown()},
			},
			"name": schema.StringAttribute{
				Description:         "Name of the network.",
				MarkdownDescription: "Name of the network.",
				Required:            true,
			},
			"ip_address": schema.StringAttribute{
				Description:         "IP address of the network.",
				MarkdownDescription: "IP address of the network.",
				Optional:            true,
			},
			"prefix_length": schema.Int64Attribute{
				Description:         "Prefix length of the network.",
				MarkdownDescription: "Prefix length of the network.",
				Required:            true,
			},
			"is_dynamic": schema.BoolAttribute{
				Description:         "Whether the network has a dynamic IP address.",
				MarkdownDescription: "Whether the network has a dynamic IP address.",
				Required:            true,
			},
			"status": schema.StringAttribute{
				Description:         "Status of the network. Valid values are OPEN or CLOSED.",
				MarkdownDescription: "Status of the network. Valid values are `OPEN` or `CLOSED`.",
				Required:            true,
			},
			"created_at": schema.StringAttribute{
				Description:         "RFC3339 timestamp of when the network was created.",
				MarkdownDescription: "RFC3339 timestamp of when the network was created.",
				Computed:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
		},
	}
}

func (r *networkResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id, err := strconv.ParseInt(req.ID, 10, 64)
	if err != nil {
		resp.Diagnostics.AddError(
			"Invalid import ID",
			fmt.Sprintf("Expected numeric network ID, got: %s", req.ID),
		)
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), id)...)
}

func (r *networkResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	tflog.Info(ctx, "Creating Network")

	var plan networkResourceModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	planRep, _ := json.Marshal(plan)
	tflog.Debug(ctx, "Local network definition", map[string]interface{}{"definition": string(planRep)})

	name := plan.Name.ValueString()
	createNetworkRequest := *networks.NewCreateNetworkRequest(name, plan.PrefixLength.ValueInt64(), plan.IsDynamic.ValueBool(), plan.Status.ValueString())
	if !plan.IpAddress.IsNull() {
		createNetworkRequest.SetIpAddress(plan.IpAddress.ValueString())
	}

	createResp, _, err := r.client.NetworksAPI.CreateNetwork(ctx).CreateNetworkRequest(createNetworkRequest).Execute()
	if err != nil {
		resp.Diagnostics.AddError(
			"Error creating network",
			fmt.Sprintf("Failed to create network '%s': %v", name, err),
		)
		return
	}

	tflog.Debug(ctx, "Created network", map[string]interface{}{"id": createResp.GetOriginId(), "name": name})
	updateNetworkModelFromObject(&plan, createResp)

	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *networkResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state networkResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	networkId := state.Id.ValueInt64()
	tflog.Debug(ctx, "Reading network", map[string]interface{}{"id": networkId})

	readResp, httpRes, err := r.client.NetworksAPI.GetNetwork(ctx, networkId).Execute()
	if httpRes != nil && httpRes.StatusCode == 404 {
		tflog.Info(ctx, "Network not found, removing from state", map[string]interface{}{"id": networkId})
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError(
			"Error reading network",
			fmt.Sprintf("Could not read network ID %d: %s", networkId, err.Error()),
		)
		return
	}
	if httpRes == nil {
		resp.Diagnostics.AddError(
			"HTTP Response Error",
			fmt.Sprintf("Received nil HTTP response while reading network ID %d", networkId),
		)
		return
	}

	updateNetworkModelFromObject(&state, readResp)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *networkResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	tflog.Info(ctx, "Updating Network")

	var plan, state networkResourceModel
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

	networkId := plan.Id.ValueInt64()
	updateNetworkRequest := *networks.NewUpdateNetworkRequest(plan.Name.ValueString(), plan.IsDynamic.ValueBool(), plan.Status.ValueString())
	updateNetworkRequest.SetPrefixLength(plan.PrefixLength.ValueInt64())
	if !plan.IpAddress.IsNull() {
		updateNetworkRequest.SetIpAddress(plan.IpAddress.ValueString())
	}

	updateResp, _, err := r.client.NetworksAPI.UpdateNetwork(ctx, networkId).UpdateNetworkRequest(updateNetworkRequest).Execute()
	if err != nil {
		resp.Diagnostics.AddError(
			"Error updating network",
			fmt.Sprintf("Could not update network ID %d: %s", networkId, err.Error()),
		)
		return
	}

	tflog.Debug(ctx, "Updated network", map[string]interface{}{"id": networkId})

	if updateResp != nil {
		updateNetworkModelFromObject(&state, updateResp)
	} else {
		state.Name = plan.Name
		state.IpAddress = plan.IpAddress
		state.PrefixLength = plan.PrefixLength
		state.IsDynamic = plan.IsDynamic
		state.Status = plan.Status
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *networkResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state networkResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	networkId := state.Id.ValueInt64()
	tflog.Info(ctx, "Deleting network", map[string]interface{}{"id": networkId})

	_, httpRes, err := r.client.NetworksAPI.DeleteNetwork(ctx, networkId).Execute()
	if httpRes != nil && httpRes.StatusCode == 404 {
		tflog.Info(ctx, "Network already deleted", map[string]interface{}{"id": networkId})
		return
	}
	if err != nil {
		resp.Diagnostics.AddError(
			"Error deleting network",
			fmt.Sprintf("Could not delete network ID %d: %s", networkId, err.Error()),
		)
		return
	}

	tflog.Info(ctx, "Successfully deleted network", map[string]interface{}{"id": networkId})
}

func updateNetworkModelFromObject(model *networkResourceModel, network *networks.NetworkObject) {
	model.Id = types.Int64Value(network.GetOriginId())
	model.Name = types.StringValue(network.GetName())
	model.IpAddress = types.StringValue(network.GetIpAddress())
	model.PrefixLength = types.Int64Value(network.GetPrefixLength())
	model.IsDynamic = types.BoolValue(network.GetIsDynamic())
	model.Status = types.StringValue(network.GetStatus())
	model.CreatedAt = types.StringValue(network.GetCreatedAt().Format("2006-01-02T15:04:05Z07:00"))
}

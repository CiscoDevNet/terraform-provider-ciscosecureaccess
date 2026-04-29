// Copyright 2025 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"

	"github.com/CiscoDevNet/go-ciscosecureaccess/client"
	"github.com/CiscoDevNet/go-ciscosecureaccess/internalnetworks"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ resource.Resource              = &internalNetworkResource{}
	_ resource.ResourceWithConfigure = &internalNetworkResource{}
)

// NewInternalNetworkResource is a helper function to simplify the provider implementation.
func NewInternalNetworkResource() resource.Resource {
	return &internalNetworkResource{}
}

// internalNetworkResource is the resource implementation.
type internalNetworkResource struct {
	client internalnetworks.APIClient
}

// internalNetworkResourceModel maps the data schema data.
type internalNetworkResourceModel struct {
	Id           types.Int64  `tfsdk:"id"`
	Name         types.String `tfsdk:"name"`
	IpAddress    types.String `tfsdk:"ip_address"`
	PrefixLength types.Int64  `tfsdk:"prefix_length"`
	SiteId       types.Int64  `tfsdk:"site_id"`
	NetworkId    types.Int64  `tfsdk:"network_id"`
	TunnelId     types.Int64  `tfsdk:"tunnel_id"`
	SiteName     types.String `tfsdk:"site_name"`
	NetworkName  types.String `tfsdk:"network_name"`
	TunnelName   types.String `tfsdk:"tunnel_name"`
}

// Metadata returns the resource type name.
func (r *internalNetworkResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_internal_network"
}

// Configure adds the provider configured client to the resource.
func (r *internalNetworkResource) Configure(ctx context.Context, req resource.ConfigureRequest, _ *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	r.client = *req.ProviderData.(*client.SSEClientFactory).GetInternalNetworksClient(ctx)
}

// Schema defines the schema for the resource.
func (r *internalNetworkResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages an Internal Network in the Cisco Secure Access organization. Specify one of: site_id, network_id, or tunnel_id.",
		Attributes: map[string]schema.Attribute{
			"id": schema.Int64Attribute{
				Description: "Origin ID of the Internal Network (used as the unique identifier).",
				Computed:    true,
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				Description: "Name of the Internal Network. Must be between 1 and 50 characters.",
				Required:    true,
			},
			"ip_address": schema.StringAttribute{
				Description:   "IP (IPv4 or IPv6) address of the Internal Network.",
				Required:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"prefix_length": schema.Int64Attribute{
				Description:   "Prefix length of the Internal Network. Must be between 8 and 32.",
				Required:      true,
				PlanModifiers: []planmodifier.Int64{int64planmodifier.RequiresReplace()},
			},
			"site_id": schema.Int64Attribute{
				Description: "ID of the Site to associate with this Internal Network. Specify one of: site_id, network_id, or tunnel_id.",
				Optional:    true,
			},
			"network_id": schema.Int64Attribute{
				Description: "ID of the Network to associate with this Internal Network. Specify one of: site_id, network_id, or tunnel_id.",
				Optional:    true,
			},
			"tunnel_id": schema.Int64Attribute{
				Description: "ID of the Network Tunnel Group to associate with this Internal Network. Specify one of: site_id, network_id, or tunnel_id.",
				Optional:    true,
			},
			"site_name": schema.StringAttribute{
				Description: "Name of the Site associated with this Internal Network.",
				Computed:    true,
			},
			"network_name": schema.StringAttribute{
				Description: "Name of the Network associated with this Internal Network.",
				Computed:    true,
			},
			"tunnel_name": schema.StringAttribute{
				Description: "Name of the Network Tunnel Group associated with this Internal Network.",
				Computed:    true,
			},
		},
	}
}

// Create creates the resource and sets the initial Terraform state.
func (r *internalNetworkResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	tflog.Info(ctx, "Creating Internal Network")

	var plan internalNetworkResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	createRequest := *internalnetworks.NewCreateInternalNetworkRequest(
		plan.Name.ValueString(),
		plan.IpAddress.ValueString(),
		plan.PrefixLength.ValueInt64(),
	)

	if !plan.SiteId.IsNull() && !plan.SiteId.IsUnknown() {
		v := plan.SiteId.ValueInt64()
		createRequest.SetSiteId(v)
	}
	if !plan.NetworkId.IsNull() && !plan.NetworkId.IsUnknown() {
		v := plan.NetworkId.ValueInt64()
		createRequest.SetNetworkId(v)
	}
	if !plan.TunnelId.IsNull() && !plan.TunnelId.IsUnknown() {
		v := plan.TunnelId.ValueInt64()
		createRequest.SetTunnelId(v)
	}

	createResp, _, err := r.client.InternalNetworksAPI.CreateInternalNetwork(ctx).CreateInternalNetworkRequest(createRequest).Execute()
	if err != nil {
		resp.Diagnostics.AddError(
			"Error creating Internal Network",
			fmt.Sprintf("Could not create internal network '%s': %s", plan.Name.ValueString(), err),
		)
		return
	}

	tflog.Debug(ctx, "Created internal network", map[string]interface{}{
		"id":   createResp.GetOriginId(),
		"name": createResp.GetName(),
	})

	flattenInternalNetworkObject(createResp, &plan)

	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

// Read refreshes the Terraform state with the latest data.
func (r *internalNetworkResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state internalNetworkResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	networkId := state.Id.ValueInt64()
	tflog.Debug(ctx, "Reading internal network", map[string]interface{}{"id": networkId})

	getResp, httpRes, err := r.client.InternalNetworksAPI.GetInternalNetwork(ctx, networkId).Execute()
	if httpRes != nil && httpRes.StatusCode == 404 {
		tflog.Info(ctx, "Internal network not found, removing from state", map[string]interface{}{"id": networkId})
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError(
			"Error reading Internal Network",
			fmt.Sprintf("Could not read internal network ID %d: %s", networkId, err),
		)
		return
	}

	flattenInternalNetworkObject(getResp, &state)

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *internalNetworkResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	tflog.Info(ctx, "Updating Internal Network")

	var plan, state internalNetworkResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	networkId := state.Id.ValueInt64()
	plan.Id = state.Id

	updateRequest := *internalnetworks.NewCreateInternalNetworkRequest(
		plan.Name.ValueString(),
		plan.IpAddress.ValueString(),
		plan.PrefixLength.ValueInt64(),
	)

	if !plan.SiteId.IsNull() && !plan.SiteId.IsUnknown() {
		v := plan.SiteId.ValueInt64()
		updateRequest.SetSiteId(v)
	}
	if !plan.NetworkId.IsNull() && !plan.NetworkId.IsUnknown() {
		v := plan.NetworkId.ValueInt64()
		updateRequest.SetNetworkId(v)
	}
	if !plan.TunnelId.IsNull() && !plan.TunnelId.IsUnknown() {
		v := plan.TunnelId.ValueInt64()
		updateRequest.SetTunnelId(v)
	}

	updateResp, _, err := r.client.InternalNetworksAPI.UpdateInternalNetwork(ctx, networkId).CreateInternalNetworkRequest(updateRequest).Execute()
	if err != nil {
		resp.Diagnostics.AddError(
			"Error updating Internal Network",
			fmt.Sprintf("Could not update internal network ID %d: %s", networkId, err),
		)
		return
	}

	tflog.Debug(ctx, "Updated internal network", map[string]interface{}{"id": networkId})

	flattenInternalNetworkObject(updateResp, &plan)

	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

// Delete deletes the resource and removes the Terraform state on success.
func (r *internalNetworkResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state internalNetworkResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	networkId := state.Id.ValueInt64()
	tflog.Debug(ctx, "Deleting internal network", map[string]interface{}{"id": networkId})

	httpRes, err := r.client.InternalNetworksAPI.DeleteInternalNetwork(ctx, networkId).Execute()
	if httpRes != nil && httpRes.StatusCode == 404 {
		return
	}
	if err != nil {
		resp.Diagnostics.AddError(
			"Error deleting Internal Network",
			fmt.Sprintf("Could not delete internal network ID %d: %s", networkId, err),
		)
		return
	}

	tflog.Debug(ctx, "Deleted internal network", map[string]interface{}{"id": networkId})
}

// flattenInternalNetworkObject maps API response fields to the Terraform state model.
func flattenInternalNetworkObject(network *internalnetworks.InternalNetworkObject, model *internalNetworkResourceModel) {
	model.Id = types.Int64Value(network.GetOriginId())
	model.Name = types.StringValue(network.GetName())
	model.IpAddress = types.StringValue(network.GetIpAddress())
	model.PrefixLength = types.Int64Value(network.GetPrefixLength())

	if v, ok := network.GetSiteIdOk(); ok && v != nil {
		model.SiteId = types.Int64Value(*v)
	} else if model.SiteId.IsUnknown() {
		model.SiteId = types.Int64Null()
	}

	if v, ok := network.GetNetworkIdOk(); ok && v != nil {
		model.NetworkId = types.Int64Value(*v)
	} else if model.NetworkId.IsUnknown() {
		model.NetworkId = types.Int64Null()
	}

	if v, ok := network.GetTunnelIdOk(); ok && v != nil {
		model.TunnelId = types.Int64Value(*v)
	} else if model.TunnelId.IsUnknown() {
		model.TunnelId = types.Int64Null()
	}

	if v, ok := network.GetSiteNameOk(); ok && v != nil {
		model.SiteName = types.StringValue(*v)
	} else {
		model.SiteName = types.StringNull()
	}

	if v, ok := network.GetNetworkNameOk(); ok && v != nil {
		model.NetworkName = types.StringValue(*v)
	} else {
		model.NetworkName = types.StringNull()
	}

	if v, ok := network.GetTunnelNameOk(); ok && v != nil {
		model.TunnelName = types.StringValue(*v)
	} else {
		model.TunnelName = types.StringNull()
	}

}

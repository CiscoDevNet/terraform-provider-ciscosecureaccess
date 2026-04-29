// Copyright 2025 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"

	"github.com/CiscoDevNet/go-ciscosecureaccess/client"
	"github.com/CiscoDevNet/go-ciscosecureaccess/sites"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/boolplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ resource.Resource              = &siteResource{}
	_ resource.ResourceWithConfigure = &siteResource{}
)

// NewSiteResource is a helper function to simplify the provider implementation.
func NewSiteResource() resource.Resource {
	return &siteResource{}
}

// siteResource is the resource implementation.
type siteResource struct {
	client sites.APIClient
}

// siteResourceModel maps the data schema data.
type siteResourceModel struct {
	Id                   types.Int64  `tfsdk:"id"`
	Name                 types.String `tfsdk:"name"`
	OriginId             types.Int64  `tfsdk:"origin_id"`
	IsDefault            types.Bool   `tfsdk:"is_default"`
	Type                 types.String `tfsdk:"type"`
	InternalNetworkCount types.Int64  `tfsdk:"internal_network_count"`
	VaCount              types.Int64  `tfsdk:"va_count"`
}

// Metadata returns the resource type name.
func (r *siteResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_site"
}

// Configure adds the provider configured client to the resource.
func (r *siteResource) Configure(ctx context.Context, req resource.ConfigureRequest, _ *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	r.client = *req.ProviderData.(*client.SSEClientFactory).GetSitesClient(ctx)
}

// Schema defines the schema for the resource.
func (r *siteResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages a Site in the Cisco Secure Access organization.",
		Attributes: map[string]schema.Attribute{
			"id": schema.Int64Attribute{
				Description: "Unique ID of the Site.",
				Computed:    true,
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				Description: "Name of the Site. Must be between 1 and 255 characters.",
				Required:    true,
			},
			"origin_id": schema.Int64Attribute{
				Description: "Origin ID of the Site.",
				Computed:    true,
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.UseStateForUnknown(),
				},
			},
			"is_default": schema.BoolAttribute{
				Description: "Specifies whether the Site is the default Site.",
				Computed:    true,
				PlanModifiers: []planmodifier.Bool{
					boolplanmodifier.UseStateForUnknown(),
				},
			},
			"type": schema.StringAttribute{
				Description: "Type of the Site.",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"internal_network_count": schema.Int64Attribute{
				Description: "Number of internal networks associated with the Site.",
				Computed:    true,
			},
			"va_count": schema.Int64Attribute{
				Description: "Number of virtual appliances associated with the Site.",
				Computed:    true,
			},
		},
	}
}

// Create creates the resource and sets the initial Terraform state.
func (r *siteResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	tflog.Info(ctx, "Creating Site")

	var plan siteResourceModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	createSiteRequest := *sites.NewCreateSiteRequest(plan.Name.ValueString())

	createResp, _, err := r.client.SitesAPI.CreateSite(ctx).CreateSiteRequest(createSiteRequest).Execute()
	if err != nil {
		resp.Diagnostics.AddError(
			"Error creating Site",
			fmt.Sprintf("Could not create site '%s': %s", plan.Name.ValueString(), err),
		)
		return
	}

	tflog.Debug(ctx, "Created site", map[string]interface{}{
		"id":   createResp.GetSiteId(),
		"name": createResp.GetName(),
	})

	flattenSiteObject(createResp, &plan)

	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
}

// Read refreshes the Terraform state with the latest data.
func (r *siteResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state siteResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	siteId := state.Id.ValueInt64()
	tflog.Debug(ctx, "Reading site", map[string]interface{}{"id": siteId})

	getResp, httpRes, err := r.client.SitesAPI.GetSite(ctx, siteId).Execute()
	if httpRes != nil && httpRes.StatusCode == 404 {
		tflog.Info(ctx, "Site not found, removing from state", map[string]interface{}{"id": siteId})
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError(
			"Error reading Site",
			fmt.Sprintf("Could not read site ID %d: %s", siteId, err),
		)
		return
	}

	flattenSiteObject(getResp, &state)

	diags = resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *siteResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	tflog.Info(ctx, "Updating Site")

	var plan, state siteResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	siteId := state.Id.ValueInt64()
	plan.Id = state.Id

	updateRequest := *sites.NewCreateSiteRequest(plan.Name.ValueString())

	updateResp, _, err := r.client.SitesAPI.UpdateSite(ctx, siteId).CreateSiteRequest(updateRequest).Execute()
	if err != nil {
		resp.Diagnostics.AddError(
			"Error updating Site",
			fmt.Sprintf("Could not update site ID %d: %s", siteId, err),
		)
		return
	}

	tflog.Debug(ctx, "Updated site", map[string]interface{}{"id": siteId})

	flattenSiteObject(updateResp, &plan)

	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

// Delete deletes the resource and removes the Terraform state on success.
func (r *siteResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state siteResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	siteId := state.Id.ValueInt64()
	tflog.Debug(ctx, "Deleting site", map[string]interface{}{"id": siteId})

	httpRes, err := r.client.SitesAPI.DeleteSite(ctx, siteId).Execute()
	if httpRes != nil && httpRes.StatusCode == 404 {
		return
	}
	if err != nil {
		resp.Diagnostics.AddError(
			"Error deleting Site",
			fmt.Sprintf("Could not delete site ID %d: %s", siteId, err),
		)
		return
	}

	tflog.Debug(ctx, "Deleted site", map[string]interface{}{"id": siteId})
}

// flattenSiteObject maps API response fields to the Terraform state model.
func flattenSiteObject(site *sites.SiteObject, model *siteResourceModel) {
	model.Id = types.Int64Value(site.GetSiteId())
	model.Name = types.StringValue(site.GetName())
	model.OriginId = types.Int64Value(site.GetOriginId())
	model.IsDefault = types.BoolValue(site.GetIsDefault())

	if v, ok := site.GetTypeOk(); ok && v != nil {
		model.Type = types.StringValue(*v)
	} else {
		model.Type = types.StringNull()
	}

	if v, ok := site.GetInternalNetworkCountOk(); ok && v != nil {
		model.InternalNetworkCount = types.Int64Value(*v)
	} else {
		model.InternalNetworkCount = types.Int64Null()
	}

	if v, ok := site.GetVaCountOk(); ok && v != nil {
		model.VaCount = types.Int64Value(*v)
	} else {
		model.VaCount = types.Int64Null()
	}
}

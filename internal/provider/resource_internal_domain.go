// Copyright 2025 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/CiscoDevNet/go-ciscosecureaccess/client"
	"github.com/CiscoDevNet/go-ciscosecureaccess/internaldomains"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ resource.Resource                   = &internalDomainResource{}
	_ resource.ResourceWithConfigure      = &internalDomainResource{}
	_ resource.ResourceWithImportState    = &internalDomainResource{}
	_ resource.ResourceWithValidateConfig = &internalDomainResource{}
)

// NewInternalDomainResource is a helper function to simplify the provider implementation.
func NewInternalDomainResource() resource.Resource {
	return &internalDomainResource{}
}

// internalDomainResource is the resource implementation.
type internalDomainResource struct {
	client internaldomains.APIClient
}

// internalDomainResourceModel maps the data schema data.
type internalDomainResourceModel struct {
	Id                      types.Int64  `tfsdk:"id"`
	Domain                  types.String `tfsdk:"domain"`
	Description             types.String `tfsdk:"description"`
	IncludeAllVAs           types.Bool   `tfsdk:"include_all_vas"`
	IncludeAllMobileDevices types.Bool   `tfsdk:"include_all_mobile_devices"`
	SiteIds                 types.List   `tfsdk:"site_ids"`
	CreatedAt               types.String `tfsdk:"created_at"`
	ModifiedAt              types.String `tfsdk:"modified_at"`
}

// Metadata returns the resource type name.
func (r *internalDomainResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_internal_domain"
}

// Configure adds the provider configured client to the resource.
func (r *internalDomainResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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
	r.client = *factory.GetInternalDomainsClient(ctx)
}

// Schema defines the schema for the resource.
func (r *internalDomainResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description:         "Manages a Cisco Secure Access Internal Domain resource. Internal domains define which DNS domains are resolved internally via the Secure Access tunnel.",
		MarkdownDescription: "Manages a Cisco Secure Access Internal Domain resource. Internal domains define which DNS domains are resolved internally via the Secure Access tunnel.",
		Version:             0,
		Attributes: map[string]schema.Attribute{
			"id": schema.Int64Attribute{
				Description:         "Unique ID of the internal domain.",
				MarkdownDescription: "Unique ID of the internal domain.",
				Computed:            true,
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.UseStateForUnknown(),
				},
			},
			"domain": schema.StringAttribute{
				Description:         "The domain name to be resolved internally (e.g. corp.example.com). Changing this forces a new resource.",
				MarkdownDescription: "The domain name to be resolved internally (e.g. `corp.example.com`). Changing this forces a new resource.",
				Required:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"description": schema.StringAttribute{
				Description:         "Human-readable description for the internal domain.",
				MarkdownDescription: "Human-readable description for the internal domain.",
				Optional:            true,
				Computed:            true,
			},
			"include_all_vas": schema.BoolAttribute{
				Description:         "When true, applies the internal domain to all virtual appliances. Mutually exclusive with site_ids.",
				MarkdownDescription: "When `true`, applies the internal domain to all virtual appliances. Mutually exclusive with `site_ids`.",
				Optional:            true,
				Computed:            true,
			},
			"include_all_mobile_devices": schema.BoolAttribute{
				Description:         "When true, applies the internal domain to all mobile devices.",
				MarkdownDescription: "When `true`, applies the internal domain to all mobile devices.",
				Optional:            true,
				Computed:            true,
			},
			"site_ids": schema.ListAttribute{
				Description:         "List of site IDs to associate with this internal domain. Mutually exclusive with include_all_vas = true.",
				MarkdownDescription: "List of site IDs to associate with this internal domain. Mutually exclusive with `include_all_vas = true`.",
				Optional:            true,
				ElementType:         types.Int64Type,
			},
			"created_at": schema.StringAttribute{
				Description:         "RFC3339 timestamp of when the internal domain was created.",
				MarkdownDescription: "RFC3339 timestamp of when the internal domain was created.",
				Computed:            true,
			},
			"modified_at": schema.StringAttribute{
				Description:         "RFC3339 timestamp of when the internal domain was last modified.",
				MarkdownDescription: "RFC3339 timestamp of when the internal domain was last modified.",
				Computed:            true,
			},
		},
	}
}

// Create creates the resource and sets the initial Terraform state.
func (r *internalDomainResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	tflog.Info(ctx, "Creating Internal Domain")

	var plan internalDomainResourceModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if planRep, err := json.Marshal(plan); err == nil {
		tflog.Debug(ctx, "Local internal domain definition", map[string]interface{}{"definition": string(planRep)})
	}

	domain := plan.Domain.ValueString()
	createInternalDomainRequest := buildInternalDomainRequest(ctx, plan, resp.Diagnostics.AddError)
	if resp.Diagnostics.HasError() {
		return
	}

	createResp, _, err := r.client.InternalDomainsAPI.CreateInternalDomain(ctx).CreateInternalDomainRequest(createInternalDomainRequest).Execute()
	if err != nil {
		resp.Diagnostics.AddError(
			"Error creating internal domain",
			fmt.Sprintf("Failed to create internal domain '%s': %v", domain, err),
		)
		return
	}

	tflog.Debug(ctx, "Created internal domain", map[string]interface{}{
		"id":     createResp.GetId(),
		"domain": domain,
	})

	setInternalDomainState(ctx, createResp, &plan, resp.Diagnostics.AddError)
	if resp.Diagnostics.HasError() {
		return
	}

	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
}

// Read refreshes the Terraform state with the latest data.
func (r *internalDomainResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state internalDomainResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	internalDomainId := state.Id.ValueInt64()
	tflog.Debug(ctx, "Reading internal domain", map[string]interface{}{"id": internalDomainId})

	readResp, httpRes, err := r.client.InternalDomainsAPI.GetInternalDomain(ctx, internalDomainId).Execute()
	if httpRes != nil && httpRes.StatusCode == 404 {
		tflog.Info(ctx, "Internal domain not found, removing from state", map[string]interface{}{"id": internalDomainId})
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError(
			"Error reading internal domain",
			fmt.Sprintf("Could not read internal domain ID %d: %s", internalDomainId, err.Error()),
		)
		return
	}
	if httpRes == nil {
		resp.Diagnostics.AddError(
			"HTTP Response Error",
			fmt.Sprintf("Received nil HTTP response while reading internal domain ID %d", internalDomainId),
		)
		return
	}

	setInternalDomainState(ctx, readResp, &state, resp.Diagnostics.AddError)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *internalDomainResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	tflog.Info(ctx, "Updating Internal Domain")

	var plan, state internalDomainResourceModel
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

	internalDomainId := plan.Id.ValueInt64()
	updateInternalDomainRequest := buildInternalDomainRequest(ctx, plan, resp.Diagnostics.AddError)
	if resp.Diagnostics.HasError() {
		return
	}

	updateResp, _, err := r.client.InternalDomainsAPI.UpdateInternalDomain(ctx, internalDomainId).CreateInternalDomainRequest(updateInternalDomainRequest).Execute()
	if err != nil {
		resp.Diagnostics.AddError(
			"Error updating internal domain",
			fmt.Sprintf("Could not update internal domain ID %d: %s", internalDomainId, err.Error()),
		)
		return
	}

	tflog.Debug(ctx, "Updated internal domain", map[string]interface{}{"id": internalDomainId})

	setInternalDomainState(ctx, updateResp, &state, resp.Diagnostics.AddError)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// Delete deletes the resource and removes the Terraform state on success.
func (r *internalDomainResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state internalDomainResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	internalDomainId := state.Id.ValueInt64()
	tflog.Info(ctx, "Deleting internal domain", map[string]interface{}{"id": internalDomainId})

	_, httpRes, err := r.client.InternalDomainsAPI.DeleteInternalDomain(ctx, internalDomainId).Execute()
	if httpRes != nil && httpRes.StatusCode == 404 {
		tflog.Info(ctx, "Internal domain already deleted", map[string]interface{}{"id": internalDomainId})
		return
	}
	if err != nil {
		resp.Diagnostics.AddError(
			"Error deleting internal domain",
			fmt.Sprintf("Could not delete internal domain ID %d: %s", internalDomainId, err.Error()),
		)
		return
	}

	tflog.Info(ctx, "Successfully deleted internal domain", map[string]interface{}{"id": internalDomainId})
}

// ValidateConfig enforces that include_all_vas = true is mutually exclusive with site_ids being non-empty.
func (r *internalDomainResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var config internalDomainResourceModel
	diags := req.Config.Get(ctx, &config)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	includeAllVAsTrue := !config.IncludeAllVAs.IsNull() && !config.IncludeAllVAs.IsUnknown() && config.IncludeAllVAs.ValueBool()
	siteIdsSet := !config.SiteIds.IsNull() && !config.SiteIds.IsUnknown() && len(config.SiteIds.Elements()) > 0

	if includeAllVAsTrue && siteIdsSet {
		resp.Diagnostics.AddAttributeError(
			path.Root("include_all_vas"),
			"Conflicting configuration",
			"include_all_vas cannot be true when site_ids is set. Use either include_all_vas = true or specify site_ids, not both.",
		)
	}
}

// ImportState imports an existing resource by numeric ID.
func (r *internalDomainResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id, err := strconv.ParseInt(req.ID, 10, 64)
	if err != nil {
		resp.Diagnostics.AddError(
			"Invalid import ID",
			fmt.Sprintf("Expected numeric internal domain ID, got: %s", req.ID),
		)
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), id)...)
}

func buildInternalDomainRequest(ctx context.Context, plan internalDomainResourceModel, addError func(string, string)) internaldomains.CreateInternalDomainRequest {
	internalDomainRequest := *internaldomains.NewCreateInternalDomainRequest(plan.Domain.ValueString())

	if !plan.Description.IsNull() && !plan.Description.IsUnknown() {
		internalDomainRequest.SetDescription(plan.Description.ValueString())
	}
	if !plan.IncludeAllVAs.IsNull() && !plan.IncludeAllVAs.IsUnknown() {
		internalDomainRequest.SetIncludeAllVAs(plan.IncludeAllVAs.ValueBool())
	}
	if !plan.IncludeAllMobileDevices.IsNull() && !plan.IncludeAllMobileDevices.IsUnknown() {
		internalDomainRequest.SetIncludeAllMobileDevices(plan.IncludeAllMobileDevices.ValueBool())
	}
	if !plan.SiteIds.IsNull() && !plan.SiteIds.IsUnknown() {
		var siteIds []int64
		diags := plan.SiteIds.ElementsAs(ctx, &siteIds, false)
		if diags.HasError() {
			addError(
				"Error processing internal domain site IDs",
				"Could not convert site IDs to API request format",
			)
			return internalDomainRequest
		}
		internalDomainRequest.SetSiteIds(siteIds)
	}

	return internalDomainRequest
}

func setInternalDomainState(ctx context.Context, internalDomain *internaldomains.InternalDomainObject, state *internalDomainResourceModel, addError func(string, string)) {
	state.Id = types.Int64Value(internalDomain.GetId())
	state.Domain = types.StringValue(internalDomain.GetDomain())

	// description: only store when non-empty. If the API returns "" and the user
	// never configured it, keep state null to prevent buildInternalDomainRequest
	// from sending description:"" on unrelated updates (API rejects length < 1).
	if v := internalDomain.GetDescription(); v != "" {
		state.Description = types.StringValue(v)
	} else if state.Description.IsUnknown() {
		state.Description = types.StringNull()
	}

	// include_all_vas: only store when true, or when the user already configured it.
	// Prevents a null optional from becoming computed false and leaking into updates.
	if v := internalDomain.GetIncludeAllVAs(); v {
		state.IncludeAllVAs = types.BoolValue(true)
	} else if state.IncludeAllVAs.IsUnknown() {
		state.IncludeAllVAs = types.BoolNull()
	}

	// include_all_mobile_devices: same rationale as include_all_vas.
	if v := internalDomain.GetIncludeAllMobileDevices(); v {
		state.IncludeAllMobileDevices = types.BoolValue(true)
	} else if state.IncludeAllMobileDevices.IsUnknown() {
		state.IncludeAllMobileDevices = types.BoolNull()
	}

	state.CreatedAt = types.StringValue(formatInternalDomainTime(internalDomain.GetCreatedAt()))
	state.ModifiedAt = types.StringValue(formatInternalDomainTime(internalDomain.GetModifiedAt()))

	apiSiteIds := internalDomain.GetSiteIds()
	if len(apiSiteIds) == 0 && state.SiteIds.IsNull() {
		state.SiteIds = types.ListNull(types.Int64Type)
	} else {
		siteIds, diags := types.ListValueFrom(ctx, types.Int64Type, apiSiteIds)
		if diags.HasError() {
			addError(
				"Error processing internal domain site IDs",
				"Could not convert site IDs to terraform state format",
			)
			return
		}
		state.SiteIds = siteIds
	}
}

func formatInternalDomainTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.Format(time.RFC3339)
}

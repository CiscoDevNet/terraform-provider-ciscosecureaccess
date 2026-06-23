// Copyright 2025 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"

	"github.com/CiscoDevNet/go-ciscosecureaccess/client"
	"github.com/CiscoDevNet/go-ciscosecureaccess/ztnaprofiles"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var (
	_ resource.Resource              = &ztnaPrivateSteeringDestinationResource{}
	_ resource.ResourceWithConfigure = &ztnaPrivateSteeringDestinationResource{}
)

func NewZtnaPrivateSteeringDestinationResource() resource.Resource {
	return &ztnaPrivateSteeringDestinationResource{}
}

type ztnaPrivateSteeringDestinationResource struct {
	client *ztnaprofiles.APIClient
}

type ztnaPrivateSteeringDestinationModel struct {
	ID           types.String   `tfsdk:"id"`
	ProfileId    types.String   `tfsdk:"profile_id"`
	Endpoint     types.String   `tfsdk:"endpoint"`
	EndpointType types.String   `tfsdk:"endpoint_type"`
	Exclusions   []types.String `tfsdk:"exclusions"`
	CreatedAt    types.String   `tfsdk:"created_at"`
	ModifiedAt   types.String   `tfsdk:"modified_at"`
}

func (r *ztnaPrivateSteeringDestinationResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_ztna_private_steering_destination"
}

func (r *ztnaPrivateSteeringDestinationResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	factory, ok := req.ProviderData.(*client.SSEClientFactory)
	if !ok {
		resp.Diagnostics.AddError("Unexpected Provider Data Type",
			fmt.Sprintf("expected *client.SSEClientFactory, got %T", req.ProviderData))
		return
	}
	r.client = factory.GetZtnaProfilesClient(ctx)
}

func (r *ztnaPrivateSteeringDestinationResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages a manually created private steering destination for a ZTNA profile.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "Unique ID of the private steering destination.",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"profile_id": schema.StringAttribute{
				Description: "ID of the ZTNA profile.",
				Required:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"endpoint": schema.StringAttribute{
				Description: "Domain or CIDR endpoint for this private steering destination.",
				Required:    true,
			},
			"endpoint_type": schema.StringAttribute{
				Description: "Type of the endpoint (domain, ip, etc.).",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"exclusions": schema.ListAttribute{
				Description: "Subdomains or sub-ranges to exclude from this destination.",
				Optional:    true,
				Computed:    true,
				ElementType: types.StringType,
			},
			"created_at": schema.StringAttribute{
				Description: "Timestamp when this destination was created.",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"modified_at": schema.StringAttribute{
				Description: "Timestamp when this destination was last modified.",
				Computed:    true,
			},
		},
	}
}

func (r *ztnaPrivateSteeringDestinationResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan ztnaPrivateSteeringDestinationModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	input := ztnaprofiles.PrivateSteeringDestinationInput{
		Endpoint:   plan.Endpoint.ValueString(),
		Exclusions: typesStringSliceToStrings(plan.Exclusions),
	}

	created, _, err := r.client.ZtnaProfilesAPI.
		CreatePrivateSteeringDestination(ctx, plan.ProfileId.ValueString()).
		PrivateSteeringDestinationInput(input).
		Execute()
	if err != nil {
		resp.Diagnostics.AddError("Error creating private steering destination", err.Error())
		return
	}

	flattenPrivateSteeringDestination(created, &plan)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *ztnaPrivateSteeringDestinationResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state ztnaPrivateSteeringDestinationModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	dest, httpResp, err := r.client.ZtnaProfilesAPI.
		GetPrivateSteeringDestination(ctx, state.ProfileId.ValueString(), state.ID.ValueString()).
		Execute()
	if err != nil {
		if httpResp != nil && httpResp.StatusCode == 404 {
			tflog.Info(ctx, "Private steering destination not found, removing from state")
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Error reading private steering destination", err.Error())
		return
	}

	flattenPrivateSteeringDestination(dest, &state)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *ztnaPrivateSteeringDestinationResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state ztnaPrivateSteeringDestinationModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	input := ztnaprofiles.PrivateSteeringDestinationInput{
		Endpoint:   plan.Endpoint.ValueString(),
		Exclusions: typesStringSliceToStrings(plan.Exclusions),
	}

	updated, _, err := r.client.ZtnaProfilesAPI.
		UpdatePrivateSteeringDestination(ctx, state.ProfileId.ValueString(), state.ID.ValueString()).
		PrivateSteeringDestinationInput(input).
		Execute()
	if err != nil {
		resp.Diagnostics.AddError("Error updating private steering destination", err.Error())
		return
	}

	flattenPrivateSteeringDestination(updated, &state)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *ztnaPrivateSteeringDestinationResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state ztnaPrivateSteeringDestinationModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	httpResp, err := r.client.ZtnaProfilesAPI.
		DeletePrivateSteeringDestination(ctx, state.ProfileId.ValueString(), state.ID.ValueString()).
		Execute()
	if err != nil {
		if httpResp != nil && httpResp.StatusCode == 404 {
			return
		}
		resp.Diagnostics.AddError("Error deleting private steering destination", err.Error())
	}
}

func flattenPrivateSteeringDestination(d *ztnaprofiles.PrivateSteeringDestination, m *ztnaPrivateSteeringDestinationModel) {
	if d.Id != nil {
		m.ID = types.StringValue(*d.Id)
	}
	if d.Endpoint != nil {
		m.Endpoint = types.StringValue(*d.Endpoint)
	}
	if d.EndpointType != nil {
		m.EndpointType = types.StringValue(*d.EndpointType)
	}
	excl := make([]types.String, len(d.Exclusions))
	for i, e := range d.Exclusions {
		excl[i] = types.StringValue(e)
	}
	m.Exclusions = excl
	if d.CreatedAt != nil {
		m.CreatedAt = types.StringValue(*d.CreatedAt)
	}
	if d.ModifiedAt != nil {
		m.ModifiedAt = types.StringValue(*d.ModifiedAt)
	}
}

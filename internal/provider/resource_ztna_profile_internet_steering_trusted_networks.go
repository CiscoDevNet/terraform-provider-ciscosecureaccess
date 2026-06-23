// Copyright 2025 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"
	"net/http"

	"github.com/CiscoDevNet/go-ciscosecureaccess/client"
	"github.com/CiscoDevNet/go-ciscosecureaccess/ztnaprofiles"
	retry "github.com/avast/retry-go/v4"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var (
	_ resource.Resource              = &ztnaProfileInternetSteeringTrustedNetworksResource{}
	_ resource.ResourceWithConfigure = &ztnaProfileInternetSteeringTrustedNetworksResource{}
)

func NewZtnaProfileInternetSteeringTrustedNetworksResource() resource.Resource {
	return &ztnaProfileInternetSteeringTrustedNetworksResource{}
}

type ztnaProfileInternetSteeringTrustedNetworksResource struct {
	client *ztnaprofiles.APIClient
}

type ztnaProfileInternetSteeringTrustedNetworksModel struct {
	ProfileId         types.String   `tfsdk:"profile_id"`
	TrustedNetworkIds []types.String `tfsdk:"trusted_network_ids"`
}

func (r *ztnaProfileInternetSteeringTrustedNetworksResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_ztna_profile_internet_steering_trusted_networks"
}

func (r *ztnaProfileInternetSteeringTrustedNetworksResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *ztnaProfileInternetSteeringTrustedNetworksResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages the trusted network mappings for a ZTNA profile's internet steering configuration.",
		Attributes: map[string]schema.Attribute{
			"profile_id": schema.StringAttribute{
				Description: "ID of the ZTNA profile.",
				Required:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"trusted_network_ids": schema.ListAttribute{
				Description: "List of trusted network IDs to associate with this profile's internet steering.",
				Required:    true,
				ElementType: types.StringType,
			},
		},
	}
}

func (r *ztnaProfileInternetSteeringTrustedNetworksResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan ztnaProfileInternetSteeringTrustedNetworksModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.applyMappings(ctx, plan.ProfileId.ValueString(), nil, plan.TrustedNetworkIds); err != nil {
		resp.Diagnostics.AddError("Error creating internet steering trusted network mappings", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *ztnaProfileInternetSteeringTrustedNetworksResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state ztnaProfileInternetSteeringTrustedNetworksModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	current, httpResp, err := r.client.ZtnaProfilesAPI.ListProfileInternetSteeringTrustedNetworks(ctx, state.ProfileId.ValueString()).Execute()
	if err != nil {
		if httpResp != nil && httpResp.StatusCode == 404 {
			tflog.Info(ctx, "Profile not found, removing internet steering trusted networks from state")
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Error reading internet steering trusted network mappings", err.Error())
		return
	}
	ids := make([]types.String, len(current.Items))
	for i, item := range current.Items {
		if item.Id != nil {
			ids[i] = types.StringValue(*item.Id)
		}
	}
	state.TrustedNetworkIds = ids
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *ztnaProfileInternetSteeringTrustedNetworksResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state ztnaProfileInternetSteeringTrustedNetworksModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.applyMappings(ctx, plan.ProfileId.ValueString(), state.TrustedNetworkIds, plan.TrustedNetworkIds); err != nil {
		resp.Diagnostics.AddError("Error updating internet steering trusted network mappings", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *ztnaProfileInternetSteeringTrustedNetworksResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state ztnaProfileInternetSteeringTrustedNetworksModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.applyMappings(ctx, state.ProfileId.ValueString(), state.TrustedNetworkIds, nil); err != nil {
		resp.Diagnostics.AddError("Error deleting internet steering trusted network mappings", err.Error())
	}
}

func (r *ztnaProfileInternetSteeringTrustedNetworksResource) applyMappings(ctx context.Context, profileId string, _, desired []types.String) error {
	desiredSet := stringSliceToSet(desired)

	return retry.Do(func() error {
		live, _, err := r.client.ZtnaProfilesAPI.ListProfileInternetSteeringTrustedNetworks(ctx, profileId).Execute()
		if err != nil {
			return retry.Unrecoverable(fmt.Errorf("listing current internet trusted networks: %w", err))
		}

		liveSet := make(map[string]struct{}, len(live.Items))
		for _, item := range live.Items {
			if item.Id != nil {
				liveSet[*item.Id] = struct{}{}
			}
		}

		var ops []ztnaprofiles.ZtnaProfileAddRemoveResource
		for id := range desiredSet {
			if _, exists := liveSet[id]; !exists {
				idCopy := id
				ops = append(ops, ztnaprofiles.ZtnaProfileAddRemoveResource{
					Op:    "add",
					Path:  "/items",
					Value: &ztnaprofiles.ZtnaProfileAddResourceValue{Id: idCopy},
				})
			}
		}
		for id := range liveSet {
			if _, exists := desiredSet[id]; !exists {
				idCopy := id
				ops = append(ops, ztnaprofiles.ZtnaProfileAddRemoveResource{
					Op:    "remove",
					Path:  "/items",
					Value: &ztnaprofiles.ZtnaProfileAddResourceValue{Id: idCopy},
				})
			}
		}

		if len(ops) == 0 {
			return nil
		}

		rev := int32(0)
		if live.Rev != nil {
			rev = *live.Rev
		}

		_, httpResp, patchErr := r.client.ZtnaProfilesAPI.PatchProfileInternetSteeringTrustedNetworks(ctx, profileId).
			ZtnaProfileAddRemoveResources(ztnaprofiles.ZtnaProfileAddRemoveResources{
				Operations: ops,
				Rev:        rev,
			}).Execute()
		if patchErr != nil && httpResp != nil && httpResp.StatusCode == http.StatusConflict {
			return patchErr
		}
		if patchErr != nil {
			return retry.Unrecoverable(patchErr)
		}
		return nil
	}, retry.Attempts(5))
}

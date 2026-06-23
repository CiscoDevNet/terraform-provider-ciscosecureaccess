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
	_ resource.Resource              = &ztnaProfilePrivateSteeringTrustedNetworksResource{}
	_ resource.ResourceWithConfigure = &ztnaProfilePrivateSteeringTrustedNetworksResource{}
)

func NewZtnaProfilePrivateSteeringTrustedNetworksResource() resource.Resource {
	return &ztnaProfilePrivateSteeringTrustedNetworksResource{}
}

type ztnaProfilePrivateSteeringTrustedNetworksResource struct {
	client *ztnaprofiles.APIClient
}

type ztnaProfilePrivateSteeringTrustedNetworksModel struct {
	ProfileId         types.String   `tfsdk:"profile_id"`
	TrustedNetworkIds []types.String `tfsdk:"trusted_network_ids"`
}

func (r *ztnaProfilePrivateSteeringTrustedNetworksResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_ztna_profile_private_steering_trusted_networks"
}

func (r *ztnaProfilePrivateSteeringTrustedNetworksResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *ztnaProfilePrivateSteeringTrustedNetworksResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages the trusted network mappings for a ZTNA profile's private steering configuration.",
		Attributes: map[string]schema.Attribute{
			"profile_id": schema.StringAttribute{
				Description: "ID of the ZTNA profile.",
				Required:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"trusted_network_ids": schema.ListAttribute{
				Description: "List of trusted network IDs to associate with this profile's private steering.",
				Required:    true,
				ElementType: types.StringType,
			},
		},
	}
}

func (r *ztnaProfilePrivateSteeringTrustedNetworksResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan ztnaProfilePrivateSteeringTrustedNetworksModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.applyMappings(ctx, plan.ProfileId.ValueString(), nil, plan.TrustedNetworkIds); err != nil {
		resp.Diagnostics.AddError("Error creating private steering trusted network mappings", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *ztnaProfilePrivateSteeringTrustedNetworksResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state ztnaProfilePrivateSteeringTrustedNetworksModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	current, httpResp, err := r.client.ZtnaProfilesAPI.ListProfilePrivateSteeringTrustedNetworks(ctx, state.ProfileId.ValueString()).Execute()
	if err != nil {
		if httpResp != nil && httpResp.StatusCode == 404 {
			tflog.Info(ctx, "Profile not found, removing private steering trusted networks from state")
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Error reading private steering trusted network mappings", err.Error())
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

func (r *ztnaProfilePrivateSteeringTrustedNetworksResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state ztnaProfilePrivateSteeringTrustedNetworksModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.applyMappings(ctx, plan.ProfileId.ValueString(), state.TrustedNetworkIds, plan.TrustedNetworkIds); err != nil {
		resp.Diagnostics.AddError("Error updating private steering trusted network mappings", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *ztnaProfilePrivateSteeringTrustedNetworksResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state ztnaProfilePrivateSteeringTrustedNetworksModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.applyMappings(ctx, state.ProfileId.ValueString(), state.TrustedNetworkIds, nil); err != nil {
		resp.Diagnostics.AddError("Error deleting private steering trusted network mappings", err.Error())
	}
}

func (r *ztnaProfilePrivateSteeringTrustedNetworksResource) applyMappings(ctx context.Context, profileId string, _, desired []types.String) error {
	desiredSet := stringSliceToSet(desired)

	return retry.Do(func() error {
		live, _, err := r.client.ZtnaProfilesAPI.ListProfilePrivateSteeringTrustedNetworks(ctx, profileId).Execute()
		if err != nil {
			return retry.Unrecoverable(fmt.Errorf("listing current trusted networks: %w", err))
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

		_, httpResp, patchErr := r.client.ZtnaProfilesAPI.PatchProfilePrivateSteeringTrustedNetworks(ctx, profileId).
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

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
	_ resource.Resource              = &ztnaProfileGroupMappingsResource{}
	_ resource.ResourceWithConfigure = &ztnaProfileGroupMappingsResource{}
)

func NewZtnaProfileGroupMappingsResource() resource.Resource {
	return &ztnaProfileGroupMappingsResource{}
}

type ztnaProfileGroupMappingsResource struct {
	client *ztnaprofiles.APIClient
}

type ztnaProfileGroupMappingsModel struct {
	ProfileId types.String   `tfsdk:"profile_id"`
	GroupIds  []types.String `tfsdk:"group_ids"`
}

func (r *ztnaProfileGroupMappingsResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_ztna_profile_group_mappings"
}

func (r *ztnaProfileGroupMappingsResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *ztnaProfileGroupMappingsResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages the group ID mappings for a ZTNA profile.",
		Attributes: map[string]schema.Attribute{
			"profile_id": schema.StringAttribute{
				Description: "ID of the ZTNA profile.",
				Required:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"group_ids": schema.ListAttribute{
				Description: "List of group IDs to map to this profile.",
				Required:    true,
				ElementType: types.StringType,
			},
		},
	}
}

func (r *ztnaProfileGroupMappingsResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan ztnaProfileGroupMappingsModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.applyGroupMappings(ctx, plan.ProfileId.ValueString(), nil, plan.GroupIds); err != nil {
		resp.Diagnostics.AddError("Error creating group mappings", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *ztnaProfileGroupMappingsResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state ztnaProfileGroupMappingsModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	current, httpResp, err := r.client.ZtnaProfilesAPI.ListProfileGroups(ctx, state.ProfileId.ValueString()).Execute()
	if err != nil {
		if httpResp != nil && httpResp.StatusCode == 404 {
			tflog.Info(ctx, "Profile not found, removing group mappings from state")
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Error reading group mappings", err.Error())
		return
	}

	liveSet := make(map[string]struct{}, len(current.Items))
	for _, item := range current.Items {
		if item.Id != nil {
			liveSet[*item.Id] = struct{}{}
		}
	}

	stateSet := make(map[string]struct{}, len(state.GroupIds))
	for _, id := range state.GroupIds {
		if !id.IsNull() && !id.IsUnknown() {
			stateSet[id.ValueString()] = struct{}{}
		}
	}

	if len(liveSet) == len(stateSet) {
		same := true
		for id := range liveSet {
			if _, exists := stateSet[id]; !exists {
				same = false
				break
			}
		}
		if same {
			resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
			return
		}
	}

	ids := make([]types.String, 0, len(current.Items))
	for _, item := range current.Items {
		if item.Id != nil {
			ids = append(ids, types.StringValue(*item.Id))
		}
	}
	state.GroupIds = ids
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *ztnaProfileGroupMappingsResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state ztnaProfileGroupMappingsModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.applyGroupMappings(ctx, plan.ProfileId.ValueString(), state.GroupIds, plan.GroupIds); err != nil {
		resp.Diagnostics.AddError("Error updating group mappings", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *ztnaProfileGroupMappingsResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state ztnaProfileGroupMappingsModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.applyGroupMappings(ctx, state.ProfileId.ValueString(), state.GroupIds, nil); err != nil {
		resp.Diagnostics.AddError("Error deleting group mappings", err.Error())
	}
}

func (r *ztnaProfileGroupMappingsResource) applyGroupMappings(ctx context.Context, profileId string, _, desired []types.String) error {
	desiredSet := stringSliceToSet(desired)

	return retry.Do(func() error {
		live, _, err := r.client.ZtnaProfilesAPI.ListProfileGroups(ctx, profileId).Execute()
		if err != nil {
			return retry.Unrecoverable(fmt.Errorf("listing current groups: %w", err))
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

		_, httpResp, patchErr := r.client.ZtnaProfilesAPI.PatchProfileGroups(ctx, profileId).
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

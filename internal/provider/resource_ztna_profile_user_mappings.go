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
	_ resource.Resource              = &ztnaProfileUserMappingsResource{}
	_ resource.ResourceWithConfigure = &ztnaProfileUserMappingsResource{}
)

func NewZtnaProfileUserMappingsResource() resource.Resource {
	return &ztnaProfileUserMappingsResource{}
}

type ztnaProfileUserMappingsResource struct {
	client *ztnaprofiles.APIClient
}

type ztnaProfileUserMappingsModel struct {
	ProfileId types.String   `tfsdk:"profile_id"`
	UserIds   []types.String `tfsdk:"user_ids"`
}

func (r *ztnaProfileUserMappingsResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_ztna_profile_user_mappings"
}

func (r *ztnaProfileUserMappingsResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *ztnaProfileUserMappingsResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages the user ID mappings for a ZTNA profile.",
		Attributes: map[string]schema.Attribute{
			"profile_id": schema.StringAttribute{
				Description: "ID of the ZTNA profile.",
				Required:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"user_ids": schema.ListAttribute{
				Description: "List of user IDs to map to this profile.",
				Required:    true,
				ElementType: types.StringType,
			},
		},
	}
}

func (r *ztnaProfileUserMappingsResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan ztnaProfileUserMappingsModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.applyUserMappings(ctx, plan.ProfileId.ValueString(), nil, plan.UserIds); err != nil {
		resp.Diagnostics.AddError("Error creating user mappings", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *ztnaProfileUserMappingsResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state ztnaProfileUserMappingsModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	current, httpResp, err := r.client.ZtnaProfilesAPI.ListProfileUsers(ctx, state.ProfileId.ValueString()).Execute()
	if err != nil {
		if httpResp != nil && httpResp.StatusCode == 404 {
			tflog.Info(ctx, "Profile not found, removing user mappings from state")
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Error reading user mappings", err.Error())
		return
	}
	ids := make([]types.String, len(current.Items))
	for i, item := range current.Items {
		if item.Id != nil {
			ids[i] = types.StringValue(*item.Id)
		}
	}
	state.UserIds = ids
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *ztnaProfileUserMappingsResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state ztnaProfileUserMappingsModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.applyUserMappings(ctx, plan.ProfileId.ValueString(), state.UserIds, plan.UserIds); err != nil {
		resp.Diagnostics.AddError("Error updating user mappings", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *ztnaProfileUserMappingsResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state ztnaProfileUserMappingsModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.applyUserMappings(ctx, state.ProfileId.ValueString(), state.UserIds, nil); err != nil {
		resp.Diagnostics.AddError("Error deleting user mappings", err.Error())
	}
}

func (r *ztnaProfileUserMappingsResource) applyUserMappings(ctx context.Context, profileId string, _, desired []types.String) error {
	desiredSet := stringSliceToSet(desired)

	return retry.Do(func() error {
		live, _, err := r.client.ZtnaProfilesAPI.ListProfileUsers(ctx, profileId).Execute()
		if err != nil {
			return retry.Unrecoverable(fmt.Errorf("listing current users: %w", err))
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

		_, httpResp, patchErr := r.client.ZtnaProfilesAPI.PatchProfileUsers(ctx, profileId).
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

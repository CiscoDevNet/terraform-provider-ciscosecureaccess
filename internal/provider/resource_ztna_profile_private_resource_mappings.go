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
	_ resource.Resource              = &ztnaProfilePrivateResourceMappingsResource{}
	_ resource.ResourceWithConfigure = &ztnaProfilePrivateResourceMappingsResource{}
)

func NewZtnaProfilePrivateResourceMappingsResource() resource.Resource {
	return &ztnaProfilePrivateResourceMappingsResource{}
}

type ztnaProfilePrivateResourceMappingsResource struct {
	client *ztnaprofiles.APIClient
}

type ztnaProfilePrivateResourceMappingsModel struct {
	ProfileId          types.String   `tfsdk:"profile_id"`
	PrivateResourceIds []types.String `tfsdk:"private_resource_ids"`
}

func (r *ztnaProfilePrivateResourceMappingsResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_ztna_profile_private_resource_mappings"
}

func (r *ztnaProfilePrivateResourceMappingsResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *ztnaProfilePrivateResourceMappingsResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages the private resource mappings for a ZTNA profile. Creates and removes mappings via PATCH operations.",
		Attributes: map[string]schema.Attribute{
			"profile_id": schema.StringAttribute{
				Description: "ID of the ZTNA profile.",
				Required:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"private_resource_ids": schema.ListAttribute{
				Description: "List of private resource IDs to map to this profile.",
				Required:    true,
				ElementType: types.StringType,
			},
		},
	}
}

func (r *ztnaProfilePrivateResourceMappingsResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan ztnaProfilePrivateResourceMappingsModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if err := r.applyMappings(ctx, plan.ProfileId.ValueString(), plan.PrivateResourceIds); err != nil {
		resp.Diagnostics.AddError("Error creating private resource mappings", err.Error())
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *ztnaProfilePrivateResourceMappingsResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state ztnaProfilePrivateResourceMappingsModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	current, httpResp, err := r.client.ZtnaProfilesAPI.ListProfilePrivateSteeringResourceMappings(ctx, state.ProfileId.ValueString()).Execute()
	if err != nil {
		if httpResp != nil && httpResp.StatusCode == 404 {
			tflog.Info(ctx, "Profile not found, removing mappings from state")
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Error reading private resource mappings", err.Error())
		return
	}

	ids := make([]types.String, len(current.Items))
	for i, item := range current.Items {
		if item.Id != nil {
			ids[i] = types.StringValue(*item.Id)
		}
	}
	state.PrivateResourceIds = ids
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *ztnaProfilePrivateResourceMappingsResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state ztnaProfilePrivateResourceMappingsModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if err := r.applyMappings(ctx, plan.ProfileId.ValueString(), plan.PrivateResourceIds); err != nil {
		resp.Diagnostics.AddError("Error updating private resource mappings", err.Error())
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *ztnaProfilePrivateResourceMappingsResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state ztnaProfilePrivateResourceMappingsModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if err := r.applyMappings(ctx, state.ProfileId.ValueString(), nil); err != nil {
		resp.Diagnostics.AddError("Error deleting private resource mappings", err.Error())
	}
}

func (r *ztnaProfilePrivateResourceMappingsResource) applyMappings(ctx context.Context, profileId string, desired []types.String) error {
	desiredSet := stringSliceToSet(desired)

	return retry.Do(func() error {
		live, _, err := r.client.ZtnaProfilesAPI.ListProfilePrivateSteeringResourceMappings(ctx, profileId).Execute()
		if err != nil {
			return retry.Unrecoverable(fmt.Errorf("listing current resources: %w", err))
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

		_, httpResp, patchErr := r.client.ZtnaProfilesAPI.PatchProfilePrivateSteeringResources(ctx, profileId).
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

func stringSliceToSet(ids []types.String) map[string]struct{} {
	out := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		if !id.IsNull() && !id.IsUnknown() {
			out[id.ValueString()] = struct{}{}
		}
	}
	return out
}

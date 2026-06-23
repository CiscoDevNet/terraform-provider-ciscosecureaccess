// Copyright 2025 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strings"

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
	_ resource.Resource              = &ztnaProfileInternetSteeringDestinationListsResource{}
	_ resource.ResourceWithConfigure = &ztnaProfileInternetSteeringDestinationListsResource{}
)

func NewZtnaProfileInternetSteeringDestinationListsResource() resource.Resource {
	return &ztnaProfileInternetSteeringDestinationListsResource{}
}

type ztnaProfileInternetSteeringDestinationListsResource struct {
	client *ztnaprofiles.APIClient
}

type ztnaProfileInternetSteeringDestinationListsModel struct {
	ProfileId        types.String                    `tfsdk:"profile_id"`
	DestinationLists []ztnaDestinationListEntryModel `tfsdk:"destination_list"`
}

type ztnaDestinationListEntryModel struct {
	ID         types.String   `tfsdk:"id"`
	Exclusions []types.String `tfsdk:"exclusions"`
}

func (r *ztnaProfileInternetSteeringDestinationListsResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_ztna_profile_internet_steering_destination_lists"
}

func (r *ztnaProfileInternetSteeringDestinationListsResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *ztnaProfileInternetSteeringDestinationListsResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages the internet steering destination list mappings for a ZTNA profile.",
		Attributes: map[string]schema.Attribute{
			"profile_id": schema.StringAttribute{
				Description: "ID of the ZTNA profile.",
				Required:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"destination_list": schema.ListNestedAttribute{
				Description: "Destination lists to map for internet steering.",
				Required:    true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							Description: "ID of the destination list.",
							Required:    true,
						},
						"exclusions": schema.ListAttribute{
							Description: "Domains excluded from this destination list's steering.",
							Optional:    true,
							ElementType: types.StringType,
						},
					},
				},
			},
		},
	}
}

func (r *ztnaProfileInternetSteeringDestinationListsResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan ztnaProfileInternetSteeringDestinationListsModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.applyMappings(ctx, plan.ProfileId.ValueString(), nil, plan.DestinationLists); err != nil {
		resp.Diagnostics.AddError("Error creating internet steering destination list mappings", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *ztnaProfileInternetSteeringDestinationListsResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state ztnaProfileInternetSteeringDestinationListsModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	current, httpResp, err := r.client.ZtnaProfilesAPI.ListProfileInternetSteeringDestinationLists(ctx, state.ProfileId.ValueString()).Execute()
	if err != nil {
		if httpResp != nil && httpResp.StatusCode == 404 {
			tflog.Info(ctx, "Profile not found, removing internet steering destination lists from state")
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Error reading internet steering destination lists", err.Error())
		return
	}
	state.DestinationLists = flattenDestinationLists(current.Items)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *ztnaProfileInternetSteeringDestinationListsResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state ztnaProfileInternetSteeringDestinationListsModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.applyMappings(ctx, plan.ProfileId.ValueString(), state.DestinationLists, plan.DestinationLists); err != nil {
		resp.Diagnostics.AddError("Error updating internet steering destination list mappings", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *ztnaProfileInternetSteeringDestinationListsResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state ztnaProfileInternetSteeringDestinationListsModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.removeMappings(ctx, state.ProfileId.ValueString()); err != nil {
		resp.Diagnostics.AddError("Error deleting internet steering destination list mappings", err.Error())
	}
}

func (r *ztnaProfileInternetSteeringDestinationListsResource) removeMappings(ctx context.Context, profileId string) error {
	return retry.Do(func() error {
		live, httpResp, err := r.client.ZtnaProfilesAPI.ListProfileInternetSteeringDestinationLists(ctx, profileId).Execute()
		if err != nil {
			if httpResp != nil && httpResp.StatusCode == http.StatusNotFound {
				return nil
			}
			return retry.Unrecoverable(fmt.Errorf("listing current destination lists: %w", err))
		}

		if len(live.Items) == 0 {
			return nil
		}

		rev := int32(0)
		if live.Rev != nil {
			rev = *live.Rev
		}

		var ops []ztnaprofiles.ZtnaProfilePatchInternetSteeringDestinationList
		for _, item := range live.Items {
			if item.Id != nil {
				ops = append(ops, ztnaprofiles.ZtnaProfilePatchInternetSteeringDestinationList{
					Op:   "remove",
					Path: "/items",
					Value: ztnaprofiles.ZtnaProfilePatchRemoveInternetSteeringDestinationList{
						Id: *item.Id,
					},
				})
			}
		}

		if len(ops) == 0 {
			return nil
		}

		_, patchResp, patchErr := r.client.ZtnaProfilesAPI.PatchProfileInternetSteeringDestinationLists(ctx, profileId).
			ZtnaProfilePatchInternetSteeringDestinationLists(ztnaprofiles.ZtnaProfilePatchInternetSteeringDestinationLists{
				Operations: ops,
				Rev:        rev,
			}).Execute()
		if patchErr != nil {
			if patchResp != nil && patchResp.StatusCode == http.StatusConflict {
				return patchErr
			}
			if patchResp != nil && patchResp.StatusCode == http.StatusBadRequest {
				tflog.Warn(ctx, "Could not remove all destination list mappings (profile may require at least one while in steering mode 2); mappings will be cleaned up when the profile is deleted")
				return nil
			}
			return retry.Unrecoverable(patchErr)
		}
		return nil
	}, retry.Attempts(5))
}

func (r *ztnaProfileInternetSteeringDestinationListsResource) applyMappings(ctx context.Context, profileId string, _, desired []ztnaDestinationListEntryModel) error {
	desiredMap := destinationListEntriesToMap(desired)

	return retry.Do(func() error {
		live, _, err := r.client.ZtnaProfilesAPI.ListProfileInternetSteeringDestinationLists(ctx, profileId).Execute()
		if err != nil {
			return retry.Unrecoverable(fmt.Errorf("listing current destination lists: %w", err))
		}

		liveMap := make(map[string][]string, len(live.Items))
		for _, item := range live.Items {
			if item.Id != nil {
				liveMap[*item.Id] = item.Exclusions
			}
		}

		rev := int32(0)
		if live.Rev != nil {
			rev = *live.Rev
		}

		var ops []ztnaprofiles.ZtnaProfilePatchInternetSteeringDestinationList

		for id, entry := range desiredMap {
			if _, exists := liveMap[id]; !exists {
				exclusions := typesStringSliceToStrings(entry.Exclusions)
				ops = append(ops, ztnaprofiles.ZtnaProfilePatchInternetSteeringDestinationList{
					Op:   "add",
					Path: "/items",
					Value: ztnaprofiles.ZtnaProfilePatchAddInternetSteeringDestinationList{
						Id:         id,
						Exclusions: exclusions,
					},
				})
			}
		}

		for id := range liveMap {
			if _, exists := desiredMap[id]; !exists {
				ops = append(ops, ztnaprofiles.ZtnaProfilePatchInternetSteeringDestinationList{
					Op:   "remove",
					Path: "/items",
					Value: ztnaprofiles.ZtnaProfilePatchRemoveInternetSteeringDestinationList{
						Id: id,
					},
				})
			}
		}

		for id, entry := range desiredMap {
			if liveExcl, exists := liveMap[id]; exists {
				desiredExcl := typesStringSliceToStrings(entry.Exclusions)
				if !stringSlicesEqual(liveExcl, desiredExcl) {
					ops = append(ops, ztnaprofiles.ZtnaProfilePatchInternetSteeringDestinationList{
						Op:   "replace",
						Path: "/items/" + id + "/exclusions",
						Value: ztnaprofiles.ZtnaProfilePatchReplaceInternetSteeringDestinationList{
							Exclusions: desiredExcl,
						},
					})
				}
			}
		}

		if len(ops) == 0 {
			return nil
		}

		_, httpResp, patchErr := r.client.ZtnaProfilesAPI.PatchProfileInternetSteeringDestinationLists(ctx, profileId).
			ZtnaProfilePatchInternetSteeringDestinationLists(ztnaprofiles.ZtnaProfilePatchInternetSteeringDestinationLists{
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

func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	aSorted := make([]string, len(a))
	bSorted := make([]string, len(b))
	copy(aSorted, a)
	copy(bSorted, b)
	sort.Strings(aSorted)
	sort.Strings(bSorted)
	return strings.Join(aSorted, "\x00") == strings.Join(bSorted, "\x00")
}

func flattenDestinationLists(items []ztnaprofiles.ZtnaProfileInternetSteeringDestinationList) []ztnaDestinationListEntryModel {
	out := make([]ztnaDestinationListEntryModel, len(items))
	for i, item := range items {
		entry := ztnaDestinationListEntryModel{}
		if item.Id != nil {
			entry.ID = types.StringValue(*item.Id)
		}
		excl := make([]types.String, len(item.Exclusions))
		for j, e := range item.Exclusions {
			excl[j] = types.StringValue(e)
		}
		entry.Exclusions = excl
		out[i] = entry
	}
	return out
}

func destinationListEntriesToMap(entries []ztnaDestinationListEntryModel) map[string]ztnaDestinationListEntryModel {
	m := make(map[string]ztnaDestinationListEntryModel, len(entries))
	for _, e := range entries {
		if !e.ID.IsNull() && !e.ID.IsUnknown() {
			m[e.ID.ValueString()] = e
		}
	}
	return m
}

func typesStringSliceToStrings(s []types.String) []string {
	out := make([]string, 0, len(s))
	for _, v := range s {
		if !v.IsNull() && !v.IsUnknown() {
			out = append(out, v.ValueString())
		}
	}
	return out
}

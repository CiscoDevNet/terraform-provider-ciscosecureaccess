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
	_ resource.Resource              = &ztnaProfileInternetSteeringExclusionsResource{}
	_ resource.ResourceWithConfigure = &ztnaProfileInternetSteeringExclusionsResource{}
)

func NewZtnaProfileInternetSteeringExclusionsResource() resource.Resource {
	return &ztnaProfileInternetSteeringExclusionsResource{}
}

type ztnaProfileInternetSteeringExclusionsResource struct {
	client *ztnaprofiles.APIClient
}

type ztnaProfileInternetSteeringExclusionsModel struct {
	ProfileId  types.String                        `tfsdk:"profile_id"`
	Exclusions []ztnaInternetSteeringExclusionItem `tfsdk:"exclusion"`
}

type ztnaInternetSteeringExclusionItem struct {
	Destination types.String `tfsdk:"destination"`
	Description types.String `tfsdk:"description"`
}

func (r *ztnaProfileInternetSteeringExclusionsResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_ztna_profile_internet_steering_exclusions"
}

func (r *ztnaProfileInternetSteeringExclusionsResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *ztnaProfileInternetSteeringExclusionsResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages the internet steering exclusions for a ZTNA profile.",
		Attributes: map[string]schema.Attribute{
			"profile_id": schema.StringAttribute{
				Description: "ID of the ZTNA profile.",
				Required:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"exclusion": schema.ListNestedAttribute{
				Description: "Internet steering exclusions.",
				Required:    true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"destination": schema.StringAttribute{
							Description: "Domain or IP to exclude from internet steering.",
							Required:    true,
						},
						"description": schema.StringAttribute{
							Description: "Human-readable description for the exclusion.",
							Optional:    true,
							Computed:    true,
							PlanModifiers: []planmodifier.String{
								stringplanmodifier.UseStateForUnknown(),
							},
						},
					},
				},
			},
		},
	}
}

func (r *ztnaProfileInternetSteeringExclusionsResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan ztnaProfileInternetSteeringExclusionsModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.applyExclusions(ctx, plan.ProfileId.ValueString(), plan.Exclusions); err != nil {
		resp.Diagnostics.AddError("Error creating internet steering exclusions", err.Error())
		return
	}
	// Refresh from API to get server-side state
	current, _, err := r.client.ZtnaProfilesAPI.ListProfileInternetSteeringExclusions(ctx, plan.ProfileId.ValueString()).Execute()
	if err != nil {
		resp.Diagnostics.AddError("Error reading exclusions after create", err.Error())
		return
	}
	plan.Exclusions = flattenExclusions(current.Items)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *ztnaProfileInternetSteeringExclusionsResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state ztnaProfileInternetSteeringExclusionsModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	current, httpResp, err := r.client.ZtnaProfilesAPI.ListProfileInternetSteeringExclusions(ctx, state.ProfileId.ValueString()).Execute()
	if err != nil {
		if httpResp != nil && httpResp.StatusCode == 404 {
			tflog.Info(ctx, "Profile not found, removing internet steering exclusions from state")
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Error reading internet steering exclusions", err.Error())
		return
	}
	state.Exclusions = flattenExclusions(current.Items)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *ztnaProfileInternetSteeringExclusionsResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state ztnaProfileInternetSteeringExclusionsModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.applyExclusions(ctx, plan.ProfileId.ValueString(), plan.Exclusions); err != nil {
		resp.Diagnostics.AddError("Error updating internet steering exclusions", err.Error())
		return
	}
	current, _, err := r.client.ZtnaProfilesAPI.ListProfileInternetSteeringExclusions(ctx, plan.ProfileId.ValueString()).Execute()
	if err != nil {
		resp.Diagnostics.AddError("Error reading exclusions after update", err.Error())
		return
	}
	state.Exclusions = flattenExclusions(current.Items)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *ztnaProfileInternetSteeringExclusionsResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state ztnaProfileInternetSteeringExclusionsModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.removeExclusions(ctx, state.ProfileId.ValueString()); err != nil {
		resp.Diagnostics.AddError("Error deleting internet steering exclusions", err.Error())
	}
}

func (r *ztnaProfileInternetSteeringExclusionsResource) removeExclusions(ctx context.Context, profileId string) error {
	return retry.Do(func() error {
		live, httpResp, err := r.client.ZtnaProfilesAPI.ListProfileInternetSteeringExclusions(ctx, profileId).Execute()
		if err != nil {
			if httpResp != nil && httpResp.StatusCode == http.StatusNotFound {
				return nil
			}
			return retry.Unrecoverable(fmt.Errorf("listing current exclusions: %w", err))
		}

		rev := int32(0)
		if live.Rev != nil {
			rev = *live.Rev
		}

		var ops []ztnaprofiles.ZtnaProfilePatchInternetSteeringExclusion
		for _, item := range live.Items {
			if item.IsGlobal != nil && *item.IsGlobal {
				continue
			}
			if item.Exclusion != nil {
				exclusion := *item.Exclusion
				ops = append(ops, ztnaprofiles.ZtnaProfilePatchInternetSteeringExclusion{
					Op:   "remove",
					Path: "/items",
					Value: &ztnaprofiles.ZtnaProfileAddRemoveReplaceInternetSteeringExclusion{
						Exclusion: &exclusion,
					},
				})
			}
		}

		if len(ops) == 0 {
			return nil
		}

		_, patchResp, patchErr := r.client.ZtnaProfilesAPI.PatchProfileInternetSteeringExclusions(ctx, profileId).
			ZtnaProfilePatchInternetSteeringExclusions(ztnaprofiles.ZtnaProfilePatchInternetSteeringExclusions{
				Operations: ops,
				Rev:        rev,
			}).Execute()
		if patchErr != nil {
			if patchResp != nil && patchResp.StatusCode == http.StatusConflict {
				return patchErr
			}
			if patchResp != nil && patchResp.StatusCode == http.StatusBadRequest {
				tflog.Warn(ctx, "Could not remove all exclusions; they will be cleaned up when the profile is deleted")
				return nil
			}
			return retry.Unrecoverable(patchErr)
		}
		return nil
	}, retry.Attempts(5))
}

func (r *ztnaProfileInternetSteeringExclusionsResource) applyExclusions(ctx context.Context, profileId string, desired []ztnaInternetSteeringExclusionItem) error {
	desiredMap := make(map[string]ztnaInternetSteeringExclusionItem)
	for _, item := range desired {
		if !item.Destination.IsNull() && !item.Destination.IsUnknown() {
			desiredMap[item.Destination.ValueString()] = item
		}
	}

	return retry.Do(func() error {
		live, _, err := r.client.ZtnaProfilesAPI.ListProfileInternetSteeringExclusions(ctx, profileId).Execute()
		if err != nil {
			return retry.Unrecoverable(fmt.Errorf("listing current exclusions: %w", err))
		}

		rev := int32(0)
		if live.Rev != nil {
			rev = *live.Rev
		}

		liveMap := make(map[string]ztnaprofiles.ZtnaProfileInternetSteeringExclusion)
		for _, item := range live.Items {
			if item.Exclusion != nil {
				liveMap[*item.Exclusion] = item
			}
		}

		var ops []ztnaprofiles.ZtnaProfilePatchInternetSteeringExclusion

		for dest, item := range desiredMap {
			if _, exists := liveMap[dest]; !exists {
				destCopy := dest
				var descPtr *string
				if !item.Description.IsNull() && !item.Description.IsUnknown() {
					s := item.Description.ValueString()
					descPtr = &s
				}
				ops = append(ops, ztnaprofiles.ZtnaProfilePatchInternetSteeringExclusion{
					Op:   "add",
					Path: "/items",
					Value: &ztnaprofiles.ZtnaProfileAddRemoveReplaceInternetSteeringExclusion{
						Exclusion:   &destCopy,
						Description: descPtr,
					},
				})
			} else {
				existing := liveMap[dest]
				desiredDesc := ""
				if !item.Description.IsNull() && !item.Description.IsUnknown() {
					desiredDesc = item.Description.ValueString()
				}
				existingDesc := ""
				if existing.Description != nil {
					existingDesc = *existing.Description
				}
				if desiredDesc != existingDesc {
					destCopy := dest
					var descPtr *string
					if desiredDesc != "" {
						descPtr = &desiredDesc
					}
					ops = append(ops, ztnaprofiles.ZtnaProfilePatchInternetSteeringExclusion{
						Op:   "replace",
						Path: "/items/" + destCopy,
						Value: &ztnaprofiles.ZtnaProfileAddRemoveReplaceInternetSteeringExclusion{
							Exclusion:   &destCopy,
							Description: descPtr,
						},
					})
				}
			}
		}

		for dest, existing := range liveMap {
			if _, exists := desiredMap[dest]; !exists {
				if existing.IsGlobal != nil && *existing.IsGlobal {
					continue
				}
				exclusion := *existing.Exclusion
				ops = append(ops, ztnaprofiles.ZtnaProfilePatchInternetSteeringExclusion{
					Op:   "remove",
					Path: "/items",
					Value: &ztnaprofiles.ZtnaProfileAddRemoveReplaceInternetSteeringExclusion{
						Exclusion: &exclusion,
					},
				})
			}
		}

		if len(ops) == 0 {
			return nil
		}

		_, httpResp, patchErr := r.client.ZtnaProfilesAPI.PatchProfileInternetSteeringExclusions(ctx, profileId).
			ZtnaProfilePatchInternetSteeringExclusions(ztnaprofiles.ZtnaProfilePatchInternetSteeringExclusions{
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

func flattenExclusions(items []ztnaprofiles.ZtnaProfileInternetSteeringExclusion) []ztnaInternetSteeringExclusionItem {
	out := make([]ztnaInternetSteeringExclusionItem, len(items))
	for i, item := range items {
		entry := ztnaInternetSteeringExclusionItem{}
		if item.Exclusion != nil {
			entry.Destination = types.StringValue(*item.Exclusion)
		}
		if item.Description != nil {
			entry.Description = types.StringValue(*item.Description)
		} else {
			entry.Description = types.StringNull()
		}
		out[i] = entry
	}
	return out
}

// Copyright 2025 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/CiscoDevNet/go-ciscosecureaccess/client"
	"github.com/CiscoDevNet/go-ciscosecureaccess/ztnaprofiles"
	retry "github.com/avast/retry-go/v4"
	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/boolplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var (
	_ resource.Resource                = &ztnaProfileResource{}
	_ resource.ResourceWithConfigure   = &ztnaProfileResource{}
	_ resource.ResourceWithImportState = &ztnaProfileResource{}
)

func NewZtnaProfileResource() resource.Resource {
	return &ztnaProfileResource{}
}

type ztnaProfileResource struct {
	client *ztnaprofiles.APIClient
}

type ztnaProfileModel struct {
	ID               types.String             `tfsdk:"id"`
	ProfileName      types.String             `tfsdk:"profile_name"`
	Priority         types.Int64              `tfsdk:"priority"`
	Rev              types.Int64              `tfsdk:"rev"`
	OrganizationId   types.String             `tfsdk:"organization_id"`
	CreatedAt        types.String             `tfsdk:"created_at"`
	ModifiedAt       types.String             `tfsdk:"modified_at"`
	SecurePrivate    *ztnaPrivateAccessModel  `tfsdk:"secure_private_access"`
	SecureInternet   *ztnaInternetAccessModel `tfsdk:"secure_internet_access"`
	OperatingSystems types.Object             `tfsdk:"operating_systems"`
	UsersData        *ztnaUsersDataModel      `tfsdk:"users_data"`
	GroupsData       *ztnaGroupsDataModel     `tfsdk:"groups_data"`
}

type ztnaPrivateAccessModel struct {
	TrustedNetworksEnabled types.Bool                 `tfsdk:"trusted_networks_enabled"`
	EnforcementPause       *ztnaEnforcementPauseModel `tfsdk:"enforcement_pause"`
	DnsSteeringDestIds     types.List                 `tfsdk:"dns_steering_destination_ids"`
}

type ztnaInternetAccessModel struct {
	SteeringMode           types.Int64                `tfsdk:"steering_mode"`
	TrustedNetworksEnabled types.Bool                 `tfsdk:"trusted_networks_enabled"`
	EnforcementPause       *ztnaEnforcementPauseModel `tfsdk:"enforcement_pause"`
}

type ztnaEnforcementPauseModel struct {
	Enabled         types.Bool  `tfsdk:"enabled"`
	DurationMinutes types.Int64 `tfsdk:"duration_minutes"`
}

type ztnaUsersDataModel struct {
	AllUsersEnabled types.Bool `tfsdk:"all_users_enabled"`
}

type ztnaGroupsDataModel struct {
	AllGroupsEnabled types.Bool `tfsdk:"all_groups_enabled"`
}

type ztnaOSPlatformModel struct {
	Enabled types.Bool `tfsdk:"enabled"`
}

type ztnaAndroidModel struct {
	GenericAndroid *ztnaOSPlatformModel `tfsdk:"generic_android"`
	KnoxAndroid    *ztnaOSPlatformModel `tfsdk:"knox_android"`
}

type ztnaOperatingSystemsModel struct {
	MacIntel *ztnaOSPlatformModel `tfsdk:"mac_intel"`
	Win      *ztnaOSPlatformModel `tfsdk:"win"`
	Linux64  *ztnaOSPlatformModel `tfsdk:"linux_64"`
	AppleIos *ztnaOSPlatformModel `tfsdk:"apple_ios"`
	Android  *ztnaAndroidModel    `tfsdk:"android"`
}

func (r *ztnaProfileResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_ztna_profile"
}

func (r *ztnaProfileResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *ztnaProfileResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	osPlatformAttrs := map[string]schema.Attribute{
		"enabled": schema.BoolAttribute{
			Description: "Whether this platform is enabled for the profile.",
			Optional:    true,
			Computed:    true,
			PlanModifiers: []planmodifier.Bool{
				boolplanmodifier.UseStateForUnknown(),
			},
		},
	}

	enforcePauseAttrs := map[string]schema.Attribute{
		"enabled": schema.BoolAttribute{
			Description: "Whether enforcement pause is active.",
			Optional:    true,
			Computed:    true,
			PlanModifiers: []planmodifier.Bool{
				boolplanmodifier.UseStateForUnknown(),
			},
		},
		"duration_minutes": schema.Int64Attribute{
			Description: "Duration in minutes for the enforcement pause.",
			Optional:    true,
			Computed:    true,
			PlanModifiers: []planmodifier.Int64{
				int64planmodifier.UseStateForUnknown(),
			},
		},
	}

	resp.Schema = schema.Schema{
		Description: "Manages a Cisco Secure Access ZTNA profile.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "Unique ID of the ZTNA profile.",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"profile_name": schema.StringAttribute{
				Description: "Display name of the ZTNA profile.",
				Required:    true,
			},
			"priority": schema.Int64Attribute{
				Description: "Priority of the ZTNA profile (lower value = higher priority).",
				Optional:    true,
				Computed:    true,
			},
			"rev": schema.Int64Attribute{
				Description: "Optimistic-concurrency revision number.",
				Computed:    true,
			},
			"organization_id": schema.StringAttribute{
				Description: "Organization ID that owns the profile.",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"created_at": schema.StringAttribute{
				Description: "Timestamp when the profile was created.",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"modified_at": schema.StringAttribute{
				Description: "Timestamp when the profile was last modified.",
				Computed:    true,
			},
			"secure_private_access": schema.SingleNestedAttribute{
				Description: "Secure private access configuration.",
				Optional:    true,
				Computed:    true,
				Attributes: map[string]schema.Attribute{
					"trusted_networks_enabled": schema.BoolAttribute{
						Description: "Whether trusted networks are enabled for private access.",
						Optional:    true,
						Computed:    true,
						PlanModifiers: []planmodifier.Bool{
							boolplanmodifier.UseStateForUnknown(),
						},
					},
					"enforcement_pause": schema.SingleNestedAttribute{
						Description: "Enforcement pause configuration.",
						Optional:    true,
						Computed:    true,
						Attributes:  enforcePauseAttrs,
					},
					"dns_steering_destination_ids": schema.ListAttribute{
						Description: "IDs of DNS steering destinations.",
						Optional:    true,
						Computed:    true,
						ElementType: types.StringType,
					},
				},
			},
			"secure_internet_access": schema.SingleNestedAttribute{
				Description: "Secure internet access configuration.",
				Optional:    true,
				Computed:    true,
				Attributes: map[string]schema.Attribute{
					"steering_mode": schema.Int64Attribute{
						Description: "Internet steering mode: 0=none, 1=all traffic, 2=by destination list.",
						Optional:    true,
						Computed:    true,
						PlanModifiers: []planmodifier.Int64{
							int64planmodifier.UseStateForUnknown(),
						},
						Validators: []validator.Int64{
							int64validator.OneOf(0, 1, 2),
						},
					},
					"trusted_networks_enabled": schema.BoolAttribute{
						Description: "Whether trusted networks are enabled for internet access.",
						Optional:    true,
						Computed:    true,
						PlanModifiers: []planmodifier.Bool{
							boolplanmodifier.UseStateForUnknown(),
						},
					},
					"enforcement_pause": schema.SingleNestedAttribute{
						Description: "Enforcement pause configuration.",
						Optional:    true,
						Computed:    true,
						Attributes:  enforcePauseAttrs,
					},
				},
			},
			"operating_systems": schema.SingleNestedAttribute{
				Description: "Per-platform enable/disable toggles for this profile. All platforms are enabled by default when omitted.",
				Optional:    true,
				Computed:    true,
				Attributes: map[string]schema.Attribute{
					"mac_intel": schema.SingleNestedAttribute{
						Description: "macOS (Intel) platform settings.",
						Optional:    true,
						Computed:    true,
						Attributes:  osPlatformAttrs,
					},
					"win": schema.SingleNestedAttribute{
						Description: "Windows platform settings.",
						Optional:    true,
						Computed:    true,
						Attributes:  osPlatformAttrs,
					},
					"linux_64": schema.SingleNestedAttribute{
						Description: "Linux (64-bit) platform settings.",
						Optional:    true,
						Computed:    true,
						Attributes:  osPlatformAttrs,
					},
					"apple_ios": schema.SingleNestedAttribute{
						Description: "iOS platform settings.",
						Optional:    true,
						Computed:    true,
						Attributes:  osPlatformAttrs,
					},
					"android": schema.SingleNestedAttribute{
						Description: "Android platform settings.",
						Optional:    true,
						Computed:    true,
						Attributes: map[string]schema.Attribute{
							"generic_android": schema.SingleNestedAttribute{
								Description: "Generic Android settings.",
								Optional:    true,
								Computed:    true,
								Attributes:  osPlatformAttrs,
							},
							"knox_android": schema.SingleNestedAttribute{
								Description: "Samsung Knox Android settings.",
								Optional:    true,
								Computed:    true,
								Attributes:  osPlatformAttrs,
							},
						},
					},
				},
			},
			"users_data": schema.SingleNestedAttribute{
				Description: "Users configuration for this profile.",
				Optional:    true,
				Computed:    true,
				Attributes: map[string]schema.Attribute{
					"all_users_enabled": schema.BoolAttribute{
						Description: "Whether all users are assigned to this profile.",
						Optional:    true,
						Computed:    true,
						PlanModifiers: []planmodifier.Bool{
							boolplanmodifier.UseStateForUnknown(),
						},
					},
				},
			},
			"groups_data": schema.SingleNestedAttribute{
				Description: "Groups configuration for this profile.",
				Optional:    true,
				Computed:    true,
				Attributes: map[string]schema.Attribute{
					"all_groups_enabled": schema.BoolAttribute{
						Description: "Whether all groups are assigned to this profile.",
						Optional:    true,
						Computed:    true,
						PlanModifiers: []planmodifier.Bool{
							boolplanmodifier.UseStateForUnknown(),
						},
					},
				},
			},
		},
	}
}

func (r *ztnaProfileResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan ztnaProfileModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	input := ztnaprofiles.ZtnaProfileCreateInput{
		ProfileName:          plan.ProfileName.ValueString(),
		Priority:             int32(plan.Priority.ValueInt64()),
		SecurePrivateAccess:  expandPrivateAccessInput(plan.SecurePrivate),
		SecureInternetAccess: expandInternetAccessInput(plan.SecureInternet),
		OperatingSystems:     expandOperatingSystemsFromObject(ctx, plan.OperatingSystems),
		UsersData:            expandUsersInput(plan.UsersData),
		GroupsData:           expandGroupsInput(plan.GroupsData),
	}

	created, httpResp, err := r.client.ZtnaProfilesAPI.CreateZtnaProfile(ctx).ZtnaProfileCreateInput(input).Execute()
	if err != nil {
		detail := ztnaProfileHTTPErrorDetail(err, httpResp)
		if httpResp != nil && (httpResp.StatusCode == http.StatusConflict || httpResp.StatusCode == http.StatusBadRequest) {
			tflog.Info(ctx, "ZTNA profile create failed, attempting to adopt existing profile", map[string]interface{}{
				"name":   input.ProfileName,
				"status": httpResp.StatusCode,
			})
			r.adoptExistingProfile(ctx, input.ProfileName, &plan, resp, httpResp.StatusCode, detail)
			return
		}
		resp.Diagnostics.AddError("Error creating ZTNA profile", detail)
		return
	}

	plannedPriority := plan.Priority
	flattenZtnaProfile(created, &plan)
	if !plannedPriority.IsNull() && !plannedPriority.IsUnknown() {
		plan.Priority = plannedPriority
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *ztnaProfileResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state ztnaProfileModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	profile, httpResp, err := r.client.ZtnaProfilesAPI.GetZtnaProfile(ctx, state.ID.ValueString()).Execute()
	if err != nil {
		if httpResp != nil && httpResp.StatusCode == 404 {
			tflog.Info(ctx, "ZTNA profile not found, removing from state", map[string]interface{}{"id": state.ID.ValueString()})
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Error reading ZTNA profile", err.Error())
		return
	}

	flattenZtnaProfile(profile, &state)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *ztnaProfileResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state ztnaProfileModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	profileId := state.ID.ValueString()
	var updated *ztnaprofiles.ZtnaProfile

	err := retry.Do(func() error {
		current, _, readErr := r.client.ZtnaProfilesAPI.GetZtnaProfile(ctx, profileId).Execute()
		if readErr != nil {
			return retry.Unrecoverable(readErr)
		}
		if current.Rev == nil {
			return retry.Unrecoverable(fmt.Errorf("API returned nil rev for profile %s", profileId))
		}

		input := ztnaprofiles.ZtnaProfileUpdateInput{
			ProfileName:          plan.ProfileName.ValueString(),
			Priority:             int32(plan.Priority.ValueInt64()),
			Rev:                  *current.Rev,
			SecurePrivateAccess:  expandPrivateAccessInput(plan.SecurePrivate),
			SecureInternetAccess: expandInternetAccessInput(plan.SecureInternet),
			OperatingSystems:     expandOperatingSystemsFromObject(ctx, plan.OperatingSystems),
			UsersData:            expandUsersInput(plan.UsersData),
			GroupsData:           expandGroupsInput(plan.GroupsData),
		}

		var putErr error
		var httpResp *http.Response
		updated, httpResp, putErr = r.client.ZtnaProfilesAPI.UpdateZtnaProfile(ctx, profileId).ZtnaProfileUpdateInput(input).Execute()
		if putErr != nil && httpResp != nil && httpResp.StatusCode == http.StatusConflict {
			return putErr
		}
		if putErr != nil {
			return retry.Unrecoverable(putErr)
		}
		return nil
	},
		retry.Attempts(5),
	)

	if err != nil {
		resp.Diagnostics.AddError("Error updating ZTNA profile", err.Error())
		return
	}

	plannedPriority := plan.Priority
	flattenZtnaProfile(updated, &state)
	if !plannedPriority.IsNull() && !plannedPriority.IsUnknown() {
		state.Priority = plannedPriority
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *ztnaProfileResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state ztnaProfileModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if state.ID.ValueString() == "default-profile" {
		tflog.Info(ctx, "Default profile cannot be deleted, removing from state only")
		return
	}

	httpResp, err := r.client.ZtnaProfilesAPI.DeleteZtnaProfile(ctx, state.ID.ValueString()).Execute()
	if err != nil {
		if httpResp != nil && httpResp.StatusCode == 404 {
			return
		}
		resp.Diagnostics.AddError("Error deleting ZTNA profile", err.Error())
	}
}

func (r *ztnaProfileResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

func (r *ztnaProfileResource) adoptExistingProfile(ctx context.Context, profileName string, plan *ztnaProfileModel, resp *resource.CreateResponse, statusCode int, createErr string) {
	profileId, searched, err := r.findExistingProfileByName(ctx, profileName)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error adopting existing ZTNA profile",
			fmt.Sprintf("Profile '%s' returned %s but could not list profiles: %v. Original error: %s", profileName, ztnaStatusLabel(statusCode), err, createErr),
		)
		return
	}
	if profileId == "" {
		resp.Diagnostics.AddError(
			"Error creating ZTNA profile",
			fmt.Sprintf("Profile '%s' returned %s and no exact name match was found in %d List API results. Original error: %s", profileName, ztnaStatusLabel(statusCode), searched, createErr),
		)
		return
	}

	profile, _, readErr := r.client.ZtnaProfilesAPI.GetZtnaProfile(ctx, profileId).Execute()
	if readErr != nil {
		resp.Diagnostics.AddError(
			"Error reading adopted ZTNA profile",
			fmt.Sprintf("Could not read profile '%s' (ID %s): %v", profileName, profileId, readErr),
		)
		return
	}

	flattenZtnaProfile(profile, plan)
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

const (
	ztnaProfileAdoptionPageLimit = int32(100)
	ztnaProfileAdoptionMaxPages  = 1000
)

func (r *ztnaProfileResource) findExistingProfileByName(ctx context.Context, profileName string) (string, int, error) {
	cursor := ""
	searched := 0

	for page := 0; page < ztnaProfileAdoptionMaxPages; page++ {
		request := r.client.ZtnaProfilesAPI.ListZtnaProfiles(ctx).Limit(ztnaProfileAdoptionPageLimit)
		if cursor != "" {
			request = request.Cursor(cursor)
		}

		listResp, _, err := request.Execute()
		if err != nil {
			return "", searched, fmt.Errorf("list ZTNA profiles at cursor %q: %w", cursor, err)
		}
		if listResp == nil {
			return "", searched, fmt.Errorf("list ZTNA profiles returned nil response at cursor %q", cursor)
		}

		for _, candidate := range listResp.Items {
			searched++
			if candidate.ProfileName == nil || *candidate.ProfileName != profileName {
				continue
			}
			if candidate.ProfileId == nil {
				return "", searched, fmt.Errorf("matched profile '%s' but List API response did not include an ID", profileName)
			}
			return *candidate.ProfileId, searched, nil
		}

		if listResp.Cursor == nil || *listResp.Cursor == "" {
			return "", searched, nil
		}
		if *listResp.Cursor == cursor {
			return "", searched, fmt.Errorf("list ZTNA profiles pagination did not advance from cursor %q", cursor)
		}
		cursor = *listResp.Cursor
	}

	return "", searched, fmt.Errorf("searched %d pages without finding profile '%s'", ztnaProfileAdoptionMaxPages, profileName)
}

func ztnaStatusLabel(statusCode int) string {
	if text := http.StatusText(statusCode); text != "" {
		return fmt.Sprintf("%d %s", statusCode, text)
	}
	return fmt.Sprintf("HTTP %d", statusCode)
}

func ztnaProfileHTTPErrorDetail(err error, httpResp *http.Response) string {
	if err == nil {
		return ""
	}

	detail := err.Error()
	if httpResp == nil || httpResp.Body == nil {
		return detail
	}

	body, readErr := io.ReadAll(httpResp.Body)
	if readErr != nil {
		return detail
	}
	httpResp.Body.Close()
	httpResp.Body = io.NopCloser(bytes.NewBuffer(body))

	bodyText := strings.TrimSpace(string(body))
	if bodyText == "" {
		return detail
	}
	return fmt.Sprintf("%s: %s", detail, bodyText)
}

// ---- helpers ----

func flattenZtnaProfile(p *ztnaprofiles.ZtnaProfile, m *ztnaProfileModel) {
	if p.ProfileId != nil {
		m.ID = types.StringValue(*p.ProfileId)
	}
	if p.ProfileName != nil {
		m.ProfileName = types.StringValue(*p.ProfileName)
	}
	if p.Priority != nil {
		m.Priority = types.Int64Value(int64(*p.Priority))
	}
	if p.Rev != nil {
		m.Rev = types.Int64Value(int64(*p.Rev))
	}
	if p.OrganizationId != nil {
		m.OrganizationId = types.StringValue(*p.OrganizationId)
	}
	if p.CreatedAt != nil {
		m.CreatedAt = types.StringValue(*p.CreatedAt)
	}
	if p.ModifiedAt != nil {
		m.ModifiedAt = types.StringValue(*p.ModifiedAt)
	}

	if p.SecurePrivateAccess != nil {
		spa := p.SecurePrivateAccess
		model := &ztnaPrivateAccessModel{}
		if spa.TrustedNetworksEnabled != nil {
			model.TrustedNetworksEnabled = types.BoolValue(*spa.TrustedNetworksEnabled)
		}
		if spa.EnforcementPause != nil {
			ep := spa.EnforcementPause
			pause := &ztnaEnforcementPauseModel{}
			if ep.Enabled != nil {
				pause.Enabled = types.BoolValue(*ep.Enabled)
			}
			if ep.DurationMinutes != nil {
				pause.DurationMinutes = types.Int64Value(int64(*ep.DurationMinutes))
			}
			model.EnforcementPause = pause
		}
		elems := make([]attr.Value, len(spa.DnsSteeringDestinations))
		for i, d := range spa.DnsSteeringDestinations {
			if d.Id != nil {
				elems[i] = types.StringValue(*d.Id)
			} else {
				elems[i] = types.StringNull()
			}
		}
		listVal, listDiags := types.ListValue(types.StringType, elems)
		if listDiags.HasError() {
			listVal = types.ListValueMust(types.StringType, []attr.Value{})
		}
		model.DnsSteeringDestIds = listVal
		m.SecurePrivate = model
	}

	if p.SecureInternetAccess != nil {
		sia := p.SecureInternetAccess
		model := &ztnaInternetAccessModel{}
		if sia.SteeringMode != nil {
			model.SteeringMode = types.Int64Value(int64(*sia.SteeringMode))
		}
		if sia.TrustedNetworksEnabled != nil {
			model.TrustedNetworksEnabled = types.BoolValue(*sia.TrustedNetworksEnabled)
		}
		if sia.EnforcementPause != nil {
			ep := sia.EnforcementPause
			pause := &ztnaEnforcementPauseModel{}
			if ep.Enabled != nil {
				pause.Enabled = types.BoolValue(*ep.Enabled)
			}
			if ep.DurationMinutes != nil {
				pause.DurationMinutes = types.Int64Value(int64(*ep.DurationMinutes))
			}
			model.EnforcementPause = pause
		}
		m.SecureInternet = model
	}

	m.OperatingSystems = flattenOperatingSystemsToObject(p.OperatingSystems)

	if p.UsersData != nil && p.UsersData.AllUsersEnabled != nil {
		m.UsersData = &ztnaUsersDataModel{
			AllUsersEnabled: types.BoolValue(*p.UsersData.AllUsersEnabled),
		}
	}

	if p.GroupsData != nil && p.GroupsData.AllGroupsEnabled != nil {
		m.GroupsData = &ztnaGroupsDataModel{
			AllGroupsEnabled: types.BoolValue(*p.GroupsData.AllGroupsEnabled),
		}
	}
}

func flattenOSPlatform(p *ztnaprofiles.ZtnaProfileOSPlatformMetadata) *ztnaOSPlatformModel {
	if p == nil {
		return nil
	}
	m := &ztnaOSPlatformModel{}
	if p.Enabled != nil {
		m.Enabled = types.BoolValue(*p.Enabled)
	}
	return m
}

func flattenOperatingSystems(p *ztnaprofiles.ZtnaProfileOSProfilesMetadata) *ztnaOperatingSystemsModel {
	if p == nil {
		return nil
	}
	m := &ztnaOperatingSystemsModel{
		MacIntel: flattenOSPlatform(p.MacIntel),
		Win:      flattenOSPlatform(p.Win),
		Linux64:  flattenOSPlatform(p.Linux64),
		AppleIos: flattenOSPlatform(p.AppleIos),
	}
	if p.Android != nil {
		m.Android = &ztnaAndroidModel{
			GenericAndroid: flattenOSPlatform(p.Android.GenericAndroid),
			KnoxAndroid:    flattenOSPlatform(p.Android.KnoxAndroid),
		}
	}
	return m
}

func expandPrivateAccessInput(m *ztnaPrivateAccessModel) *ztnaprofiles.ZtnaProfilePrivateAccessInput {
	if m == nil {
		return nil
	}
	out := &ztnaprofiles.ZtnaProfilePrivateAccessInput{}
	if !m.TrustedNetworksEnabled.IsNull() && !m.TrustedNetworksEnabled.IsUnknown() {
		v := m.TrustedNetworksEnabled.ValueBool()
		out.TrustedNetworksEnabled = &v
	}
	if m.EnforcementPause != nil {
		out.EnforcementPause = expandEnforcementPause(m.EnforcementPause)
	}
	if !m.DnsSteeringDestIds.IsNull() && !m.DnsSteeringDestIds.IsUnknown() {
		elems := m.DnsSteeringDestIds.Elements()
		for _, elem := range elems {
			sv, ok := elem.(types.String)
			if ok && !sv.IsNull() && !sv.IsUnknown() {
				s := sv.ValueString()
				out.DnsSteeringDestinations = append(out.DnsSteeringDestinations, ztnaprofiles.DnsSteeringDestination{Id: &s})
			}
		}
	}
	return out
}

func expandInternetAccessInput(m *ztnaInternetAccessModel) *ztnaprofiles.ZtnaProfileInternetAccessInput {
	if m == nil {
		return nil
	}
	out := &ztnaprofiles.ZtnaProfileInternetAccessInput{}
	if !m.SteeringMode.IsNull() && !m.SteeringMode.IsUnknown() {
		v := int32(m.SteeringMode.ValueInt64())
		out.SteeringMode = &v
	}
	if !m.TrustedNetworksEnabled.IsNull() && !m.TrustedNetworksEnabled.IsUnknown() {
		v := m.TrustedNetworksEnabled.ValueBool()
		out.TrustedNetworksEnabled = &v
	}
	if m.EnforcementPause != nil {
		out.EnforcementPause = expandEnforcementPause(m.EnforcementPause)
	}
	return out
}

func expandEnforcementPause(m *ztnaEnforcementPauseModel) *ztnaprofiles.ZtnaEnforcementPause {
	if m == nil {
		return nil
	}
	out := &ztnaprofiles.ZtnaEnforcementPause{}
	if !m.Enabled.IsNull() && !m.Enabled.IsUnknown() {
		v := m.Enabled.ValueBool()
		out.Enabled = &v
	}
	if !m.DurationMinutes.IsNull() && !m.DurationMinutes.IsUnknown() {
		v := int32(m.DurationMinutes.ValueInt64())
		out.DurationMinutes = &v
	}
	return out
}

func expandUsersInput(m *ztnaUsersDataModel) *ztnaprofiles.ZtnaProfileUsersInput {
	if m == nil {
		return nil
	}
	out := &ztnaprofiles.ZtnaProfileUsersInput{}
	if !m.AllUsersEnabled.IsNull() && !m.AllUsersEnabled.IsUnknown() {
		v := m.AllUsersEnabled.ValueBool()
		out.AllUsersEnabled = &v
	}
	return out
}

func expandGroupsInput(m *ztnaGroupsDataModel) *ztnaprofiles.ZtnaProfileGroupsInput {
	if m == nil {
		return nil
	}
	out := &ztnaprofiles.ZtnaProfileGroupsInput{}
	if !m.AllGroupsEnabled.IsNull() && !m.AllGroupsEnabled.IsUnknown() {
		v := m.AllGroupsEnabled.ValueBool()
		out.AllGroupsEnabled = &v
	}
	return out
}

func expandOSPlatform(m *ztnaOSPlatformModel) *ztnaprofiles.ZtnaProfileOSPlatformMetadata {
	if m == nil {
		return nil
	}
	out := &ztnaprofiles.ZtnaProfileOSPlatformMetadata{}
	if !m.Enabled.IsNull() && !m.Enabled.IsUnknown() {
		v := m.Enabled.ValueBool()
		out.Enabled = &v
	}
	return out
}

func expandOperatingSystemsInput(m *ztnaOperatingSystemsModel) *ztnaprofiles.ZtnaProfileOSProfilesMetadata {
	if m == nil {
		return nil
	}
	out := &ztnaprofiles.ZtnaProfileOSProfilesMetadata{
		MacIntel: expandOSPlatform(m.MacIntel),
		Win:      expandOSPlatform(m.Win),
		Linux64:  expandOSPlatform(m.Linux64),
		AppleIos: expandOSPlatform(m.AppleIos),
	}
	if m.Android != nil {
		out.Android = &ztnaprofiles.ZtnaProfileAndroidMetadata{
			GenericAndroid: expandOSPlatform(m.Android.GenericAndroid),
			KnoxAndroid:    expandOSPlatform(m.Android.KnoxAndroid),
		}
	}
	return out
}

func expandOperatingSystemsFromObject(ctx context.Context, obj types.Object) *ztnaprofiles.ZtnaProfileOSProfilesMetadata {
	if obj.IsNull() || obj.IsUnknown() {
		return nil
	}
	var m ztnaOperatingSystemsModel
	diags := obj.As(ctx, &m, basetypes.ObjectAsOptions{UnhandledNullAsEmpty: true, UnhandledUnknownAsEmpty: true})
	if diags.HasError() {
		return nil
	}
	return expandOperatingSystemsInput(&m)
}

func flattenOperatingSystemsToObject(p *ztnaprofiles.ZtnaProfileOSProfilesMetadata) types.Object {
	osPlatformAttrTypes := map[string]attr.Type{
		"enabled": types.BoolType,
	}
	androidAttrTypes := map[string]attr.Type{
		"generic_android": types.ObjectType{AttrTypes: osPlatformAttrTypes},
		"knox_android":    types.ObjectType{AttrTypes: osPlatformAttrTypes},
	}
	osAttrTypes := map[string]attr.Type{
		"mac_intel": types.ObjectType{AttrTypes: osPlatformAttrTypes},
		"win":       types.ObjectType{AttrTypes: osPlatformAttrTypes},
		"linux_64":  types.ObjectType{AttrTypes: osPlatformAttrTypes},
		"apple_ios": types.ObjectType{AttrTypes: osPlatformAttrTypes},
		"android":   types.ObjectType{AttrTypes: androidAttrTypes},
	}

	if p == nil {
		return types.ObjectNull(osAttrTypes)
	}

	flatPlatform := func(pl *ztnaprofiles.ZtnaProfileOSPlatformMetadata) attr.Value {
		if pl == nil {
			return types.ObjectNull(osPlatformAttrTypes)
		}
		vals := map[string]attr.Value{
			"enabled": types.BoolValue(false),
		}
		if pl.Enabled != nil {
			vals["enabled"] = types.BoolValue(*pl.Enabled)
		}
		obj, _ := types.ObjectValue(osPlatformAttrTypes, vals)
		return obj
	}

	var androidVal attr.Value
	if p.Android == nil {
		androidVal = types.ObjectNull(androidAttrTypes)
	} else {
		androidAttrs := map[string]attr.Value{
			"generic_android": flatPlatform(p.Android.GenericAndroid),
			"knox_android":    flatPlatform(p.Android.KnoxAndroid),
		}
		obj, _ := types.ObjectValue(androidAttrTypes, androidAttrs)
		androidVal = obj
	}

	vals := map[string]attr.Value{
		"mac_intel": flatPlatform(p.MacIntel),
		"win":       flatPlatform(p.Win),
		"linux_64":  flatPlatform(p.Linux64),
		"apple_ios": flatPlatform(p.AppleIos),
		"android":   androidVal,
	}
	obj, _ := types.ObjectValue(osAttrTypes, vals)
	return obj
}

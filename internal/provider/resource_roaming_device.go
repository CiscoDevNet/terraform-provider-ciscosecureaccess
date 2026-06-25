package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/CiscoDevNet/go-ciscosecureaccess/client"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var (
	_ resource.Resource                = &roamingDeviceResource{}
	_ resource.ResourceWithConfigure   = &roamingDeviceResource{}
	_ resource.ResourceWithImportState = &roamingDeviceResource{}
)

func NewRoamingDeviceResource() resource.Resource {
	return &roamingDeviceResource{}
}

type roamingDeviceResource struct {
	factory *client.SSEClientFactory
}

type roamingDeviceModel struct {
	ID             types.String `tfsdk:"id"`
	OrganizationID types.String `tfsdk:"organization_id"`
	APIKey         types.String `tfsdk:"api_key"`
	DeviceKey      types.String `tfsdk:"device_key"`
	Platform       types.String `tfsdk:"platform"`
	UserID         types.String `tfsdk:"user_id"`
	Fingerprint    types.String `tfsdk:"fingerprint"`
	Label          types.String `tfsdk:"label"`
	OriginTypeName types.String `tfsdk:"origin_type_name"`
	DeviceID       types.String `tfsdk:"device_id"`
	OriginID       types.Int64  `tfsdk:"origin_id"`
}

type roamingDeviceCreateRequest struct {
	DeviceKey      string `json:"deviceKey"`
	Platform       string `json:"platform"`
	UserID         string `json:"userId"`
	Fingerprint    string `json:"fingerprint"`
	Label          string `json:"label"`
	OriginTypeName string `json:"originTypeName"`
}

type roamingDeviceCreateResponse struct {
	DeviceID  string `json:"deviceId"`
	DeviceKey string `json:"deviceKey"`
	UserID    int64  `json:"userId"`
	OriginID  int64  `json:"originId"`
}

func (r *roamingDeviceResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_roaming_device"
}

func (r *roamingDeviceResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	factory, ok := req.ProviderData.(*client.SSEClientFactory)
	if !ok {
		resp.Diagnostics.AddError("Unexpected Provider Data Type",
			fmt.Sprintf("expected *client.SSEClientFactory, got %T", req.ProviderData))
		return
	}
	r.factory = factory
}

func (r *roamingDeviceResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Registers a roaming device on Cisco Secure Access via the OpenDNS API for SWG scale testing.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "Terraform resource ID (same as device_id).",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"organization_id": schema.StringAttribute{
				Description: "Organization ID to register the device under.",
				Required:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"api_key": schema.StringAttribute{
				Description: "OpenDNS API key for device registration.",
				Required:    true,
				Sensitive:   true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"device_key": schema.StringAttribute{
				Description: "Unique device key identifier.",
				Required:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"platform": schema.StringAttribute{
				Description: "Platform of the device (e.g. Windows, Mac, Linux).",
				Required:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"user_id": schema.StringAttribute{
				Description: "User ID associated with the device. If empty, auto-derived from the org info API.",
				Optional:    true,
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"fingerprint": schema.StringAttribute{
				Description: "Device fingerprint. If empty, auto-derived from the org info API.",
				Optional:    true,
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"label": schema.StringAttribute{
				Description: "Display label for the device.",
				Required:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"origin_type_name": schema.StringAttribute{
				Description: "Origin type name (e.g. anyconnect).",
				Required:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"device_id": schema.StringAttribute{
				Description: "Device ID returned by the API after registration.",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"origin_id": schema.Int64Attribute{
				Description: "Origin ID returned by the API after registration.",
				Computed:    true,
			},
		},
	}
}

func (r *roamingDeviceResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan roamingDeviceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	orgID := plan.OrganizationID.ValueString()
	apiKey := plan.APIKey.ValueString()

	roamingClient := r.factory.GetRoamingClient(ctx)

	userID := plan.UserID.ValueString()
	fingerprint := plan.Fingerprint.ValueString()

	if userID == "" || fingerprint == "" {
		orgInfo, _, orgErr := roamingClient.OrganizationInformationAPI.GetOrganizationInfo(ctx).Execute()
		if orgErr != nil {
			resp.Diagnostics.AddError("Error fetching org info for roaming device registration",
				fmt.Sprintf("Failed to get userId/fingerprint from org info API: %s", orgErr.Error()))
			return
		}
		if userID == "" {
			userID = fmt.Sprintf("%d", orgInfo.UserId)
		}
		if fingerprint == "" {
			fingerprint = orgInfo.Fingerprint
		}
		tflog.Debug(ctx, "Resolved org info for roaming device", map[string]interface{}{
			"user_id":     userID,
			"fingerprint": fingerprint,
		})
	}

	body := roamingDeviceCreateRequest{
		DeviceKey:      plan.DeviceKey.ValueString(),
		Platform:       plan.Platform.ValueString(),
		UserID:         userID,
		Fingerprint:    fingerprint,
		Label:          plan.Label.ValueString(),
		OriginTypeName: plan.OriginTypeName.ValueString(),
	}

	existing, _, listErr := roamingClient.RoamingComputersAPI.ListRoamingComputers(ctx).
		Name(plan.DeviceKey.ValueString()).Limit(100).Execute()
	if listErr == nil {
		for _, dev := range existing {
			if dev.Name == plan.DeviceKey.ValueString() {
				tflog.Info(ctx, "Roaming device already exists, adopting", map[string]interface{}{
					"device_key": dev.Name,
					"device_id":  dev.DeviceId,
					"origin_id":  dev.OriginId,
				})
				plan.DeviceID = types.StringValue(dev.DeviceId)
				plan.OriginID = types.Int64Value(dev.OriginId)
				plan.ID = types.StringValue(dev.DeviceId)
				plan.UserID = types.StringValue(userID)
				plan.Fingerprint = types.StringValue(fingerprint)
				resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
				return
			}
		}
	}

	jsonBody, err := json.Marshal(body)
	if err != nil {
		resp.Diagnostics.AddError("Error marshaling request", err.Error())
		return
	}

	url := fmt.Sprintf("https://api.opendns.com/v3/organizations/%s/roamingdevices/?api-key=%s", orgID, apiKey)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(jsonBody))
	if err != nil {
		resp.Diagnostics.AddError("Error creating HTTP request", err.Error())
		return
	}
	httpReq.Header.Set("Content-Type", "application/json")

	tflog.Debug(ctx, "Registering roaming device", map[string]interface{}{
		"device_key": body.DeviceKey,
		"org_id":     orgID,
	})

	httpResp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		resp.Diagnostics.AddError("Error registering roaming device", err.Error())
		return
	}
	defer httpResp.Body.Close()

	respBody, _ := io.ReadAll(httpResp.Body)

	if httpResp.StatusCode < 200 || httpResp.StatusCode >= 300 {
		resp.Diagnostics.AddError("Error registering roaming device",
			fmt.Sprintf("HTTP %d: %s", httpResp.StatusCode, string(respBody)))
		return
	}

	var created roamingDeviceCreateResponse
	if err := json.Unmarshal(respBody, &created); err != nil {
		resp.Diagnostics.AddError("Error parsing response", fmt.Sprintf("%s\nBody: %s", err.Error(), string(respBody)))
		return
	}

	plan.DeviceID = types.StringValue(created.DeviceID)
	plan.OriginID = types.Int64Value(created.OriginID)
	plan.ID = types.StringValue(created.DeviceID)
	plan.UserID = types.StringValue(userID)
	plan.Fingerprint = types.StringValue(fingerprint)

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *roamingDeviceResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state roamingDeviceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	deviceID := state.DeviceID.ValueString()
	roamingClient := r.factory.GetRoamingClient(ctx)

	device, httpResp, err := roamingClient.RoamingComputersAPI.GetRoamingComputer(ctx, deviceID).Execute()
	if err != nil {
		if httpResp != nil && httpResp.StatusCode == http.StatusNotFound {
			tflog.Info(ctx, "Roaming device not found, removing from state", map[string]interface{}{"device_id": deviceID})
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Error reading roaming device",
			fmt.Sprintf("failed to get device %s: %s", deviceID, err.Error()))
		return
	}

	state.OriginID = types.Int64Value(device.OriginId)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *roamingDeviceResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	resp.Diagnostics.AddError(
		"Update not supported",
		"Roaming device resources do not support in-place updates. All changes require replacement.",
	)
}

func (r *roamingDeviceResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state roamingDeviceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	deviceID := state.DeviceID.ValueString()
	roamingClient := r.factory.GetRoamingClient(ctx)

	httpResp, err := roamingClient.RoamingComputersAPI.DeleteRoamingComputer(ctx, deviceID).Execute()
	if err != nil {
		if httpResp != nil && (httpResp.StatusCode == http.StatusNotFound || httpResp.StatusCode == http.StatusBadRequest) {
			tflog.Warn(ctx, "Roaming device delete returned non-success, removing from state", map[string]interface{}{
				"device_id": deviceID,
				"status":    httpResp.StatusCode,
			})
			return
		}
		resp.Diagnostics.AddError("Error deleting roaming device",
			fmt.Sprintf("failed to delete device %s: %s", deviceID, err.Error()))
	}
}

func (r *roamingDeviceResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}


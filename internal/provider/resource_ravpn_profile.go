// Copyright 2025 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"

	"github.com/CiscoDevNet/go-ciscosecureaccess/client"
	"github.com/CiscoDevNet/go-ciscosecureaccess/ravpnprofiles"
	retry "github.com/avast/retry-go/v4"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var (
	_ resource.Resource                = &ravpnProfileResource{}
	_ resource.ResourceWithConfigure   = &ravpnProfileResource{}
	_ resource.ResourceWithImportState = &ravpnProfileResource{}
)

func NewRavpnProfileResource() resource.Resource {
	return &ravpnProfileResource{}
}

type ravpnProfileResource struct {
	client *ravpnprofiles.APIClient
}

// --------------------------------------------------------------------------
// Terraform model structs
// --------------------------------------------------------------------------

type ravpnProfileModel struct {
	ID                     types.String                      `tfsdk:"id"`
	Name                   types.String                      `tfsdk:"name"`
	OrganizationID         types.String                      `tfsdk:"organization_id"`
	Rev                    types.Int64                       `tfsdk:"rev"`
	DefaultDomain          types.String                      `tfsdk:"default_domain"`
	AuthenticationType     types.Int64                       `tfsdk:"authentication_type"`
	AccountingType         types.Int64                       `tfsdk:"accounting_type"`
	AuthorizationType      types.Int64                       `tfsdk:"authorization_type"`
	BypassEnabled          types.Bool                        `tfsdk:"bypass_enabled"`
	DnsID                  types.String                      `tfsdk:"dns_id"`
	IPVersionMode          *ravpnIPVersionModeModel          `tfsdk:"ip_version_mode"`
	AuthenticationSettings *ravpnAuthenticationSettingsModel `tfsdk:"authentication_settings"`
	Saml                   *ravpnSamlModel                   `tfsdk:"saml"`
	ClientProfile          *ravpnClientProfileModel          `tfsdk:"client_profile"`
	IPPools                *ravpnIPPoolsModel                `tfsdk:"ip_pools"`
	AdvancedSettings       *ravpnAdvancedSettingsModel       `tfsdk:"advanced_settings"`
}

type ravpnIPVersionModeModel struct {
	IPv4 types.Bool `tfsdk:"ipv4"`
	IPv6 types.Bool `tfsdk:"ipv6"`
}

type ravpnAuthenticationSettingsModel struct {
	AuthenticationTimeout *ravpnTimeoutSettingModel `tfsdk:"authentication_timeout"`
	DisconnectOnIdle      *ravpnTimeoutSettingModel `tfsdk:"disconnect_on_idle"`
}

type ravpnTimeoutSettingModel struct {
	Enabled types.Bool  `tfsdk:"enabled"`
	Timeout types.Int64 `tfsdk:"timeout"`
}

type ravpnSamlModel struct {
	Configuration       types.Int64                  `tfsdk:"configuration"`
	MetadataXmlSettings *ravpnSamlMetadataXmlModel   `tfsdk:"metadata_xml_settings"`
}

type ravpnSamlMetadataXmlModel struct {
	IdpMetadataXmlFileName types.String `tfsdk:"idp_metadata_xml_file_name"`
	IdpMetadataXml         types.String `tfsdk:"idp_metadata_xml"`
}

type ravpnClientProfileModel struct {
	TunnelProtocol types.Int64              `tfsdk:"tunnel_protocol"`
	LocalLanAccess types.Int64              `tfsdk:"local_lan_access"`
	SplitTunneling *ravpnSplitTunnelingModel `tfsdk:"split_tunneling"`
}

type ravpnSplitTunnelingModel struct {
	Enabled   types.Bool   `tfsdk:"enabled"`
	RouteType types.Int64  `tfsdk:"route_type"`
	Domains   types.String `tfsdk:"domains"`
}

type ravpnIPPoolsModel struct {
	Configuration  types.Int64              `tfsdk:"configuration"`
	RegionToIpPool []ravpnRegionToIpPoolModel `tfsdk:"region_to_ip_pool"`
}

type ravpnRegionToIpPoolModel struct {
	RegionID    types.String `tfsdk:"region_id"`
	NamedPoolID types.String `tfsdk:"named_pool_id"`
}

type ravpnAdvancedSettingsModel struct {
	EnableDtls        types.Bool               `tfsdk:"enable_dtls"`
	MtuValue          types.Int64              `tfsdk:"mtu_value"`
	KeepaliveInterval types.Int64              `tfsdk:"keepalive_interval"`
	KeepaliveRetries  types.Int64              `tfsdk:"keepalive_retries"`
	DeadPeerDetection types.Int64              `tfsdk:"dead_peer_detection"`
	RekeyInterval     types.Int64              `tfsdk:"rekey_interval"`
	LoginMessage      types.String             `tfsdk:"login_message"`
	BannerMessage     types.String             `tfsdk:"banner_message"`
	MaxConnectionTime *ravpnMaxConnTimeModel   `tfsdk:"max_connection_time"`
}

type ravpnMaxConnTimeModel struct {
	Enabled types.Bool  `tfsdk:"enabled"`
	Value   types.Int64 `tfsdk:"value"`
}

// --------------------------------------------------------------------------
// Resource interface methods
// --------------------------------------------------------------------------

func (r *ravpnProfileResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_ravpn_profile"
}

func (r *ravpnProfileResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	factory, ok := req.ProviderData.(*client.SSEClientFactory)
	if !ok {
		resp.Diagnostics.AddError("Unexpected Provider Data Type",
			fmt.Sprintf("expected *client.SSEClientFactory, got %T", req.ProviderData))
		return
	}
	r.client = factory.GetRavpnProfilesClient(ctx)
}

func (r *ravpnProfileResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	timeoutAttrs := map[string]schema.Attribute{
		"enabled": schema.BoolAttribute{
			Description: "Whether the timeout is enabled.",
			Optional:    true,
		},
		"timeout": schema.Int64Attribute{
			Description: "Timeout value in seconds.",
			Optional:    true,
		},
	}

	resp.Schema = schema.Schema{
		Description: "Manages a Cisco Secure Access RAVPN VPN profile.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "Unique ID of the VPN profile.",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				Description: "Name of the VPN profile. Used as the URL identifier.",
				Required:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"organization_id": schema.StringAttribute{
				Description: "Organization ID that owns the profile.",
				Required:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"rev": schema.Int64Attribute{
				Description: "Optimistic-concurrency revision number.",
				Computed:    true,
			},
			"default_domain": schema.StringAttribute{
				Description: "Default domain for the VPN profile.",
				Required:    true,
			},
			"authentication_type": schema.Int64Attribute{
				Description: "Authentication type for the VPN profile.",
				Required:    true,
			},
			"accounting_type": schema.Int64Attribute{
				Description: "Accounting type for the VPN profile.",
				Optional:    true,
				Computed:    true,
				Default:     int64default.StaticInt64(0),
			},
			"authorization_type": schema.Int64Attribute{
				Description: "Authorization type for the VPN profile.",
				Optional:    true,
				Computed:    true,
				Default:     int64default.StaticInt64(0),
			},
			"bypass_enabled": schema.BoolAttribute{
				Description: "Whether bypass is enabled for the VPN profile.",
				Optional:    true,
			},
			"dns_id": schema.StringAttribute{
				Description: "DNS server ID for the VPN profile.",
				Optional:    true,
			},
			"ip_version_mode": schema.SingleNestedAttribute{
				Description: "IP version mode configuration.",
				Optional:    true,
				Attributes: map[string]schema.Attribute{
					"ipv4": schema.BoolAttribute{
						Description: "Whether IPv4 is enabled.",
						Optional:    true,
					},
					"ipv6": schema.BoolAttribute{
						Description: "Whether IPv6 is enabled.",
						Optional:    true,
					},
				},
			},
			"authentication_settings": schema.SingleNestedAttribute{
				Description: "Authentication settings configuration.",
				Optional:    true,
				Attributes: map[string]schema.Attribute{
					"authentication_timeout": schema.SingleNestedAttribute{
						Description: "Authentication timeout configuration.",
						Optional:    true,
						Attributes:  timeoutAttrs,
					},
					"disconnect_on_idle": schema.SingleNestedAttribute{
						Description: "Disconnect on idle configuration.",
						Optional:    true,
						Attributes:  timeoutAttrs,
					},
				},
			},
			"saml": schema.SingleNestedAttribute{
				Description: "SAML configuration.",
				Optional:    true,
				Attributes: map[string]schema.Attribute{
					"configuration": schema.Int64Attribute{
						Description: "SAML configuration type.",
						Optional:    true,
					},
					"metadata_xml_settings": schema.SingleNestedAttribute{
						Description: "SAML metadata XML settings.",
						Optional:    true,
						Attributes: map[string]schema.Attribute{
							"idp_metadata_xml_file_name": schema.StringAttribute{
								Description: "IDP metadata XML file name.",
								Optional:    true,
							},
							"idp_metadata_xml": schema.StringAttribute{
								Description: "IDP metadata XML content.",
								Optional:    true,
								Sensitive:   true,
							},
						},
					},
				},
			},
			"client_profile": schema.SingleNestedAttribute{
				Description: "Client profile configuration.",
				Optional:    true,
				Attributes: map[string]schema.Attribute{
					"tunnel_protocol": schema.Int64Attribute{
						Description: "Tunnel protocol type.",
						Optional:    true,
					},
					"local_lan_access": schema.Int64Attribute{
						Description: "Local LAN access setting.",
						Optional:    true,
					},
					"split_tunneling": schema.SingleNestedAttribute{
						Description: "Split tunneling configuration.",
						Optional:    true,
						Attributes: map[string]schema.Attribute{
							"enabled": schema.BoolAttribute{
								Description: "Whether split tunneling is enabled.",
								Optional:    true,
							},
							"route_type": schema.Int64Attribute{
								Description: "Route type for split tunneling.",
								Optional:    true,
							},
							"domains": schema.StringAttribute{
								Description: "Domains for split tunneling.",
								Optional:    true,
							},
						},
					},
				},
			},
			"ip_pools": schema.SingleNestedAttribute{
				Description: "IP pools configuration.",
				Optional:    true,
				Attributes: map[string]schema.Attribute{
					"configuration": schema.Int64Attribute{
						Description: "IP pools configuration type.",
						Optional:    true,
					},
					"region_to_ip_pool": schema.ListNestedAttribute{
						Description: "Region to IP pool mappings.",
						Optional:    true,
						NestedObject: schema.NestedAttributeObject{
							Attributes: map[string]schema.Attribute{
								"region_id": schema.StringAttribute{
									Description: "Region identifier.",
									Required:    true,
								},
								"named_pool_id": schema.StringAttribute{
									Description: "Named IP pool identifier.",
									Required:    true,
								},
							},
						},
					},
				},
			},
			"advanced_settings": schema.SingleNestedAttribute{
				Description: "Advanced settings configuration.",
				Optional:    true,
				Attributes: map[string]schema.Attribute{
					"enable_dtls": schema.BoolAttribute{
						Description: "Whether DTLS is enabled.",
						Optional:    true,
					},
					"mtu_value": schema.Int64Attribute{
						Description: "MTU value.",
						Optional:    true,
					},
					"keepalive_interval": schema.Int64Attribute{
						Description: "Keepalive interval in seconds.",
						Optional:    true,
					},
					"keepalive_retries": schema.Int64Attribute{
						Description: "Number of keepalive retries.",
						Optional:    true,
					},
					"dead_peer_detection": schema.Int64Attribute{
						Description: "Dead peer detection interval in seconds.",
						Optional:    true,
					},
					"rekey_interval": schema.Int64Attribute{
						Description: "Rekey interval in seconds.",
						Optional:    true,
					},
					"login_message": schema.StringAttribute{
						Description: "Login message displayed to users.",
						Optional:    true,
					},
					"banner_message": schema.StringAttribute{
						Description: "Banner message displayed to users.",
						Optional:    true,
					},
					"max_connection_time": schema.SingleNestedAttribute{
						Description: "Maximum connection time configuration.",
						Optional:    true,
						Attributes: map[string]schema.Attribute{
							"enabled": schema.BoolAttribute{
								Description: "Whether max connection time is enabled.",
								Optional:    true,
							},
							"value": schema.Int64Attribute{
								Description: "Maximum connection time value in minutes.",
								Optional:    true,
							},
						},
					},
				},
			},
		},
	}
}

// --------------------------------------------------------------------------
// CRUD Operations
// --------------------------------------------------------------------------

func (r *ravpnProfileResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan ravpnProfileModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	orgID := plan.OrganizationID.ValueString()
	profileName := plan.Name.ValueString()
	input := expandRavpnProfile(&plan)

	debugJSON, _ := json.Marshal(input)
	tflog.Debug(ctx, "RAVPN profile create payload", map[string]interface{}{
		"payload": string(debugJSON),
	})

	profiles, _, listErr := r.client.ProfilesAPI.ListProfiles(ctx, orgID).Execute()
	if listErr == nil {
		for _, p := range profiles {
			if p.Name == profileName {
				tflog.Info(ctx, "RAVPN profile already exists, adopting into state", map[string]interface{}{
					"profile_name": profileName,
					"profile_id":   firstNonEmpty(p.ProfileID, p.ID),
				})
				plan.ID = types.StringValue(firstNonEmpty(p.ProfileID, p.ID, p.Name))
				plan.Rev = types.Int64Value(int64(p.Rev))
				resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
				return
			}
		}
	}

	created, httpResp, err := r.client.ProfilesAPI.CreateProfile(ctx, orgID).VPNProfile(input).Execute()
	if err != nil {
		detail := ravpnHTTPErrorDetail(err, httpResp)
		resp.Diagnostics.AddError("Error creating RAVPN profile", fmt.Sprintf("%s\n\nDEBUG payload: %s", detail, string(debugJSON)))
		return
	}

	plan.ID = types.StringValue(firstNonEmpty(created.ID, created.ProfileID, created.Name))
	plan.Rev = types.Int64Value(int64(created.Rev))
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *ravpnProfileResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state ravpnProfileModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	orgID := state.OrganizationID.ValueString()
	profileName := state.Name.ValueString()

	profile, _, err := r.client.ProfilesAPI.GetProfileByName(ctx, orgID, profileName).Execute()
	if err != nil || profile == nil {
		profiles, _, listErr := r.client.ProfilesAPI.ListProfiles(ctx, orgID).Execute()
		if listErr == nil {
			for i := range profiles {
				if profiles[i].Name == profileName {
					profile = &profiles[i]
					break
				}
			}
		}
		if profile == nil {
			tflog.Info(ctx, "RAVPN profile not found, removing from state", map[string]interface{}{
				"name": profileName,
			})
			resp.State.RemoveResource(ctx)
			return
		}
	}

	state.ID = types.StringValue(firstNonEmpty(profile.ID, profile.ProfileID, profile.Name))
	state.Rev = types.Int64Value(int64(profile.Rev))
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *ravpnProfileResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state ravpnProfileModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	orgID := plan.OrganizationID.ValueString()
	profileName := state.Name.ValueString()

	var currentRev int
	updateID := profileName

	profiles, _, listErr := r.client.ProfilesAPI.ListProfiles(ctx, orgID).Execute()
	if listErr == nil {
		for _, p := range profiles {
			if p.Name == profileName {
				currentRev = p.Rev
				updateID = firstNonEmpty(p.ProfileID, p.ID, p.Name)
				break
			}
		}
	}

	var updated *ravpnprofiles.VPNProfile
	err := retry.Do(func() error {
		input := expandRavpnProfile(&plan)
		input.Rev = currentRev

		var putErr error
		var httpResp *http.Response
		updated, httpResp, putErr = r.client.ProfilesAPI.UpdateProfile(ctx, orgID, updateID).VPNProfile(input).Execute()
		if putErr != nil && httpResp != nil && httpResp.StatusCode == http.StatusConflict {
			profiles, _, _ := r.client.ProfilesAPI.ListProfiles(ctx, orgID).Execute()
			for _, p := range profiles {
				if p.Name == profileName {
					currentRev = p.Rev
					break
				}
			}
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
		resp.Diagnostics.AddError("Error updating RAVPN profile", err.Error())
		return
	}

	plan.ID = types.StringValue(firstNonEmpty(updated.ID, updated.ProfileID, updated.Name))
	plan.Rev = types.Int64Value(int64(updated.Rev))
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *ravpnProfileResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state ravpnProfileModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	orgID := state.OrganizationID.ValueString()
	profileName := state.Name.ValueString()

	deleteID := profileName
	profiles, _, listErr := r.client.ProfilesAPI.ListProfiles(ctx, orgID).Execute()
	if listErr == nil {
		for _, p := range profiles {
			if p.Name == profileName {
				deleteID = firstNonEmpty(p.ProfileID, p.ID, p.Name)
				break
			}
		}
	}

	httpResp, err := r.client.ProfilesAPI.DeleteProfile(ctx, orgID, deleteID).Execute()
	if err != nil {
		if httpResp != nil && (httpResp.StatusCode == http.StatusNotFound || httpResp.StatusCode == http.StatusBadRequest) {
			return
		}
		resp.Diagnostics.AddError("Error deleting RAVPN profile", err.Error())
	}
}

func (r *ravpnProfileResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("name"), req, resp)
}

// --------------------------------------------------------------------------
// Expand helpers (Terraform model -> SDK struct)
// --------------------------------------------------------------------------

func expandRavpnProfile(m *ravpnProfileModel) ravpnprofiles.VPNProfile {
	out := ravpnprofiles.VPNProfile{
		Name:               m.Name.ValueString(),
		DisplayName:        m.Name.ValueString(),
		DefaultDomain:      m.DefaultDomain.ValueString(),
		AuthenticationType: int(m.AuthenticationType.ValueInt64()),
		AccountingType:     int(m.AccountingType.ValueInt64()),
		AuthorizationType:  int(m.AuthorizationType.ValueInt64()),
	}

	if !m.OrganizationID.IsNull() && !m.OrganizationID.IsUnknown() {
		out.OrganizationID = m.OrganizationID.ValueString()
	}

	if !m.BypassEnabled.IsNull() && !m.BypassEnabled.IsUnknown() {
		out.BypassEnabled = m.BypassEnabled.ValueBool()
	}

	if !m.DnsID.IsNull() && !m.DnsID.IsUnknown() {
		out.DnsID = m.DnsID.ValueString()
	}

	out.IPVersionMode = expandRavpnIPVersionMode(m.IPVersionMode)
	out.AuthenticationSettings = expandRavpnAuthenticationSettings(m.AuthenticationSettings)
	out.Saml = expandRavpnSaml(m.Saml)
	out.ClientProfile = expandRavpnClientProfile(m.ClientProfile)
	out.IPPools = expandRavpnIPPools(m.IPPools)
	out.AdvancedSettings = expandRavpnAdvancedSettings(m.AdvancedSettings)

	if out.Protocol == nil {
		tlsEnabled := true
		ikev2Enabled := false
		if out.ClientProfile != nil {
			switch out.ClientProfile.TunnelProtocol {
			case 1:
				tlsEnabled = false
				ikev2Enabled = true
			case 2:
				tlsEnabled = true
				ikev2Enabled = true
			default:
				tlsEnabled = true
				ikev2Enabled = false
			}
			out.PrimaryProtocol = out.ClientProfile.TunnelProtocol
		}
		out.Protocol = &ravpnprofiles.ProtocolConfig{
			TLS:   &ravpnprofiles.ProtocolEnabled{Enabled: tlsEnabled},
			IKEv2: &ravpnprofiles.ProtocolEnabled{Enabled: ikev2Enabled},
		}
	}

	if out.TrafficSteering == nil {
		out.TrafficSteering = &ravpnprofiles.TrafficSteering{TunnelMode: 1}
	}

	if out.Saml == nil && out.AuthenticationType == 3 {
		out.Saml = &ravpnprofiles.SamlSettings{
			Configuration:  0,
			ManualSettings: &ravpnprofiles.SamlManualSettings{RequestSignature: 0},
		}
	}
	if out.Posture == nil {
		out.Posture = &ravpnprofiles.Posture{Enabled: false}
	}
	if out.WinsDns == nil {
		out.WinsDns = &ravpnprofiles.WinsDns{Configuration: 0}
	}
	if out.RadiusConfiguration == nil {
		out.RadiusConfiguration = &ravpnprofiles.RadiusConfiguration{ServerGroupIds: []string{}}
	}
	if out.UserIdentity == "" {
		out.UserIdentity = "CN"
	}
	if out.UserIdentity2 == "" {
		out.UserIdentity2 = "EA"
	}
	if out.AAA == nil {
		out.AAA = json.RawMessage(`{"authentication":{"isUsedByAllRegions":false,"AAAserverGroupRegions":null},"authorization":{"isUsedByAllRegions":false,"AAAserverGroupRegions":null},"accounting":{"isUsedByAllRegions":false,"AAAserverGroupRegions":null}}`)
	}
	if out.DnsServers == nil {
		out.DnsServers = json.RawMessage(`{"dnsRegionMappingMode":0,"regionToDnsServers":[]}`)
	}
	if out.DdnsServers == nil {
		out.DdnsServers = json.RawMessage(`{"enabled":false,"ddnsRegionMappingMode":0,"regionToDdnsServers":[]}`)
	}
	if out.ClientConfiguration == nil {
		out.ClientConfiguration = &ravpnprofiles.ClientConfiguration{
			Banner:                    &ravpnprofiles.BannerConfig{AcceptBanner: false, BannerText: ""},
			SessionTimeout:            4,
			SessionTimeoutUnit:        "hours",
			AlertBeforeSessionTimeout: 30,
			IdleTimeoutValue:          30,
			IdleTimeoutUnit:           "minutes",
			AlertBeforeIdleTimeout:    1,
			MaximumTransmissionUnit:   1390,
		}
	}
	if out.ClientSettings == nil {
		out.ClientSettings = json.RawMessage(`{"certificatePinning":false,"certificateMatching":{"keyUsage":{"decipherOnly":false,"encipherOnly":false,"crlSign":false,"keyCertSign":false,"keyAgreement":false,"dataEncipherment":false,"keyEncipherment":false,"nonRepudiation":false,"digitalSignature":false},"extendedKeyUsage":{"serverAuth":false,"clientAuth":false,"codeSign":false,"emailProtect":false,"ipsecEndSystem":false,"ipsecTunnel":false,"ipsecUser":false,"timeStamp":false,"ocspSign":false,"dvcs":false,"ikeIntermediate":false}},"customExtendedMatchKey":null,"useStartBeforeLogon":{"enabled":true,"userControllable":true},"windowsLogonEnforcement":0,"windowsVpnEstablishment":0,"linuxLogonEnforcement":0,"linuxVpnEstablishment":0,"clientCertificateStore":{"windows":0,"linux":0,"mac":0,"windowsCertStoreOverride":false},"localLanAccess":{"enabled":false,"userControllable":false},"autoReconnect":{"enabled":true,"behavior":0,"userControllable":true,"behaviorUserControllable":false},"minimizeOnConnect":{"enabled":true,"userControllable":true},"enableSecureClientScripts":{"enabled":false,"terminateScriptOnNextEvent":false,"enablePostSblOnConnectScript":true},"suspendAnyconnect":false,"rsaSecureIdIntegration":{"enabled":true,"mode":0,"userControllable":true},"clearSmartCardPin":{"enabled":true,"userControllable":false},"ipProtocolSupported":0,"automaticCertSelection":{"enabled":true,"userControllable":false},"allowLocalProxyConnections":true,"allowOptimalGatewaySelection":{"enabled":false,"userControllable":false},"proxySettings":0,"publicProxySettings":{"serverAddress":"","userControllable":false},"automaticVpnPolicy":{"enabled":false,"trustedNetworkPolicy":0,"untrustedNetworkPolicy":0,"trustedDnsDomains":"","trustedDnsServers":"","trustedServers":[],"alwaysOnVpn":{"enabled":false,"allowVpnDisconnect":true,"accessibleHostsWithVpnDisconnected":"","connectFailurePolicy":0,"allowCaptivePortalRemediation":false,"remediationTimeout":5,"applyLastVpnLocalResourceRules":false}},"captivePortalRemediation":false,"authenticationTimeout":30}`)
	}

	return out
}

func expandRavpnIPVersionMode(m *ravpnIPVersionModeModel) *ravpnprofiles.IPVersionMode {
	if m == nil {
		return nil
	}
	out := &ravpnprofiles.IPVersionMode{}
	if !m.IPv4.IsNull() && !m.IPv4.IsUnknown() {
		out.IPv4 = m.IPv4.ValueBool()
	}
	if !m.IPv6.IsNull() && !m.IPv6.IsUnknown() {
		out.IPv6 = m.IPv6.ValueBool()
	}
	return out
}

func expandRavpnAuthenticationSettings(m *ravpnAuthenticationSettingsModel) *ravpnprofiles.AuthenticationSettings {
	if m == nil {
		return nil
	}
	out := &ravpnprofiles.AuthenticationSettings{}
	if m.AuthenticationTimeout != nil {
		out.AuthenticationTimeout = expandRavpnTimeoutSetting(m.AuthenticationTimeout)
	}
	if m.DisconnectOnIdle != nil {
		out.DisconnectOnIdle = expandRavpnTimeoutSetting(m.DisconnectOnIdle)
	}
	return out
}

func expandRavpnTimeoutSetting(m *ravpnTimeoutSettingModel) *ravpnprofiles.TimeoutSetting {
	if m == nil {
		return nil
	}
	out := &ravpnprofiles.TimeoutSetting{}
	if !m.Enabled.IsNull() && !m.Enabled.IsUnknown() {
		out.Enabled = m.Enabled.ValueBool()
	}
	if !m.Timeout.IsNull() && !m.Timeout.IsUnknown() {
		out.Timeout = int(m.Timeout.ValueInt64())
	}
	return out
}

func expandRavpnSaml(m *ravpnSamlModel) *ravpnprofiles.SamlSettings {
	if m == nil {
		return nil
	}
	out := &ravpnprofiles.SamlSettings{}
	if !m.Configuration.IsNull() && !m.Configuration.IsUnknown() {
		out.Configuration = int(m.Configuration.ValueInt64())
	}
	if m.MetadataXmlSettings != nil {
		out.MetadataXmlSettings = expandRavpnSamlMetadataXml(m.MetadataXmlSettings)
	}
	return out
}

func expandRavpnSamlMetadataXml(m *ravpnSamlMetadataXmlModel) *ravpnprofiles.SamlMetadataXml {
	if m == nil {
		return nil
	}
	out := &ravpnprofiles.SamlMetadataXml{}
	if !m.IdpMetadataXmlFileName.IsNull() && !m.IdpMetadataXmlFileName.IsUnknown() {
		out.IdpMetadataXmlFileName = m.IdpMetadataXmlFileName.ValueString()
	}
	if !m.IdpMetadataXml.IsNull() && !m.IdpMetadataXml.IsUnknown() {
		out.IdpMetadataXML = m.IdpMetadataXml.ValueString()
	}
	return out
}

func expandRavpnClientProfile(m *ravpnClientProfileModel) *ravpnprofiles.ClientProfile {
	if m == nil {
		return nil
	}
	out := &ravpnprofiles.ClientProfile{}
	if !m.TunnelProtocol.IsNull() && !m.TunnelProtocol.IsUnknown() {
		proto := int(m.TunnelProtocol.ValueInt64())
		out.TunnelProtocol = proto
		out.TunnelProtocols = []int{proto}
	}
	if !m.LocalLanAccess.IsNull() && !m.LocalLanAccess.IsUnknown() {
		out.LocalLanAccess = int(m.LocalLanAccess.ValueInt64())
	}
	if m.SplitTunneling != nil {
		out.SplitTunneling = expandRavpnSplitTunneling(m.SplitTunneling)
	}
	return out
}

func expandRavpnSplitTunneling(m *ravpnSplitTunnelingModel) *ravpnprofiles.SplitTunneling {
	if m == nil {
		return nil
	}
	out := &ravpnprofiles.SplitTunneling{}
	if !m.Enabled.IsNull() && !m.Enabled.IsUnknown() {
		out.Enabled = m.Enabled.ValueBool()
	}
	if !m.RouteType.IsNull() && !m.RouteType.IsUnknown() {
		out.RouteType = int(m.RouteType.ValueInt64())
	}
	if !m.Domains.IsNull() && !m.Domains.IsUnknown() {
		out.Domains = m.Domains.ValueString()
	}
	return out
}

func expandRavpnIPPools(m *ravpnIPPoolsModel) *ravpnprofiles.IPPoolsConfig {
	if m == nil {
		return nil
	}
	out := &ravpnprofiles.IPPoolsConfig{}
	if !m.Configuration.IsNull() && !m.Configuration.IsUnknown() {
		out.Configuration = int(m.Configuration.ValueInt64())
	}
	if len(m.RegionToIpPool) > 0 {
		regions := make([]ravpnprofiles.RegionToIpPool, len(m.RegionToIpPool))
		for i, r := range m.RegionToIpPool {
			regions[i] = ravpnprofiles.RegionToIpPool{
				RegionID:    r.RegionID.ValueString(),
				NamedPoolID: r.NamedPoolID.ValueString(),
			}
		}
		out.RegionToIpPool = regions
	}
	return out
}

func expandRavpnAdvancedSettings(m *ravpnAdvancedSettingsModel) *ravpnprofiles.AdvancedSettings {
	if m == nil {
		return nil
	}
	out := &ravpnprofiles.AdvancedSettings{}
	if !m.EnableDtls.IsNull() && !m.EnableDtls.IsUnknown() {
		out.EnableDtls = m.EnableDtls.ValueBool()
	}
	if !m.MtuValue.IsNull() && !m.MtuValue.IsUnknown() {
		out.MtuValue = int(m.MtuValue.ValueInt64())
	}
	if !m.KeepaliveInterval.IsNull() && !m.KeepaliveInterval.IsUnknown() {
		out.KeepaliveInterval = int(m.KeepaliveInterval.ValueInt64())
	}
	if !m.KeepaliveRetries.IsNull() && !m.KeepaliveRetries.IsUnknown() {
		out.KeepaliveRetries = int(m.KeepaliveRetries.ValueInt64())
	}
	if !m.DeadPeerDetection.IsNull() && !m.DeadPeerDetection.IsUnknown() {
		out.DeadPeerDetection = int(m.DeadPeerDetection.ValueInt64())
	}
	if !m.RekeyInterval.IsNull() && !m.RekeyInterval.IsUnknown() {
		out.RekeyInterval = int(m.RekeyInterval.ValueInt64())
	}
	if !m.LoginMessage.IsNull() && !m.LoginMessage.IsUnknown() {
		out.LoginMessage = m.LoginMessage.ValueString()
	}
	if !m.BannerMessage.IsNull() && !m.BannerMessage.IsUnknown() {
		out.BannerMessage = m.BannerMessage.ValueString()
	}
	if m.MaxConnectionTime != nil {
		out.MaxConnectionTime = expandRavpnMaxConnTime(m.MaxConnectionTime)
	}
	return out
}

func expandRavpnMaxConnTime(m *ravpnMaxConnTimeModel) *ravpnprofiles.MaxConnTime {
	if m == nil {
		return nil
	}
	out := &ravpnprofiles.MaxConnTime{}
	if !m.Enabled.IsNull() && !m.Enabled.IsUnknown() {
		out.Enabled = m.Enabled.ValueBool()
	}
	if !m.Value.IsNull() && !m.Value.IsUnknown() {
		out.Value = int(m.Value.ValueInt64())
	}
	return out
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// --------------------------------------------------------------------------
// Flatten helpers (SDK struct -> Terraform model)
// --------------------------------------------------------------------------

func flattenRavpnProfile(p *ravpnprofiles.VPNProfile, m *ravpnProfileModel) {
	if p == nil {
		return
	}

	switch {
	case p.ID != "":
		m.ID = types.StringValue(p.ID)
	case p.ProfileID != "":
		m.ID = types.StringValue(p.ProfileID)
	default:
		m.ID = types.StringValue(p.Name)
	}
	if p.Name != "" {
		m.Name = types.StringValue(p.Name)
	}
	if p.OrganizationID != "" {
		m.OrganizationID = types.StringValue(p.OrganizationID)
	} else if p.OrgID != 0 {
		m.OrganizationID = types.StringValue(strconv.FormatInt(p.OrgID, 10))
	}
	m.Rev = types.Int64Value(int64(p.Rev))
	if p.DefaultDomain != "" {
		m.DefaultDomain = types.StringValue(p.DefaultDomain)
	}
	m.AuthenticationType = types.Int64Value(int64(p.AuthenticationType))
	m.AccountingType = types.Int64Value(int64(p.AccountingType))
	m.AuthorizationType = types.Int64Value(int64(p.AuthorizationType))
	m.BypassEnabled = types.BoolValue(p.BypassEnabled)

	if p.DnsID != "" {
		m.DnsID = types.StringValue(p.DnsID)
	}

	m.IPVersionMode = flattenRavpnIPVersionMode(p.IPVersionMode)
	m.AuthenticationSettings = flattenRavpnAuthenticationSettings(p.AuthenticationSettings)
	m.Saml = flattenRavpnSaml(p.Saml)
	m.ClientProfile = flattenRavpnClientProfile(p.ClientProfile)
	m.IPPools = flattenRavpnIPPools(p.IPPools)
	m.AdvancedSettings = flattenRavpnAdvancedSettings(p.AdvancedSettings)
}

func flattenRavpnIPVersionMode(p *ravpnprofiles.IPVersionMode) *ravpnIPVersionModeModel {
	if p == nil {
		return nil
	}
	return &ravpnIPVersionModeModel{
		IPv4: types.BoolValue(p.IPv4),
		IPv6: types.BoolValue(p.IPv6),
	}
}

func flattenRavpnAuthenticationSettings(p *ravpnprofiles.AuthenticationSettings) *ravpnAuthenticationSettingsModel {
	if p == nil {
		return nil
	}
	out := &ravpnAuthenticationSettingsModel{}
	if p.AuthenticationTimeout != nil {
		out.AuthenticationTimeout = flattenRavpnTimeoutSetting(p.AuthenticationTimeout)
	}
	if p.DisconnectOnIdle != nil {
		out.DisconnectOnIdle = flattenRavpnTimeoutSetting(p.DisconnectOnIdle)
	}
	return out
}

func flattenRavpnTimeoutSetting(p *ravpnprofiles.TimeoutSetting) *ravpnTimeoutSettingModel {
	if p == nil {
		return nil
	}
	return &ravpnTimeoutSettingModel{
		Enabled: types.BoolValue(p.Enabled),
		Timeout: types.Int64Value(int64(p.Timeout)),
	}
}

func flattenRavpnSaml(p *ravpnprofiles.SamlSettings) *ravpnSamlModel {
	if p == nil {
		return nil
	}
	out := &ravpnSamlModel{
		Configuration: types.Int64Value(int64(p.Configuration)),
	}
	if p.MetadataXmlSettings != nil {
		out.MetadataXmlSettings = flattenRavpnSamlMetadataXml(p.MetadataXmlSettings)
	}
	return out
}

func flattenRavpnSamlMetadataXml(p *ravpnprofiles.SamlMetadataXml) *ravpnSamlMetadataXmlModel {
	if p == nil {
		return nil
	}
	return &ravpnSamlMetadataXmlModel{
		IdpMetadataXmlFileName: types.StringValue(p.IdpMetadataXmlFileName),
		IdpMetadataXml:         types.StringValue(p.IdpMetadataXML),
	}
}

func flattenRavpnClientProfile(p *ravpnprofiles.ClientProfile) *ravpnClientProfileModel {
	if p == nil {
		return nil
	}
	out := &ravpnClientProfileModel{
		TunnelProtocol: types.Int64Value(int64(p.TunnelProtocol)),
		LocalLanAccess: types.Int64Value(int64(p.LocalLanAccess)),
	}
	if p.SplitTunneling != nil {
		out.SplitTunneling = flattenRavpnSplitTunneling(p.SplitTunneling)
	}
	return out
}

func flattenRavpnSplitTunneling(p *ravpnprofiles.SplitTunneling) *ravpnSplitTunnelingModel {
	if p == nil {
		return nil
	}
	return &ravpnSplitTunnelingModel{
		Enabled:   types.BoolValue(p.Enabled),
		RouteType: types.Int64Value(int64(p.RouteType)),
		Domains:   types.StringValue(p.Domains),
	}
}

func flattenRavpnIPPools(p *ravpnprofiles.IPPoolsConfig) *ravpnIPPoolsModel {
	if p == nil {
		return nil
	}
	out := &ravpnIPPoolsModel{
		Configuration: types.Int64Value(int64(p.Configuration)),
	}
	if len(p.RegionToIpPool) > 0 {
		regions := make([]ravpnRegionToIpPoolModel, len(p.RegionToIpPool))
		for i, r := range p.RegionToIpPool {
			regions[i] = ravpnRegionToIpPoolModel{
				RegionID:    types.StringValue(r.RegionID),
				NamedPoolID: types.StringValue(r.NamedPoolID),
			}
		}
		out.RegionToIpPool = regions
	}
	return out
}

func flattenRavpnAdvancedSettings(p *ravpnprofiles.AdvancedSettings) *ravpnAdvancedSettingsModel {
	if p == nil {
		return nil
	}
	out := &ravpnAdvancedSettingsModel{
		EnableDtls:        types.BoolValue(p.EnableDtls),
		MtuValue:          types.Int64Value(int64(p.MtuValue)),
		KeepaliveInterval: types.Int64Value(int64(p.KeepaliveInterval)),
		KeepaliveRetries:  types.Int64Value(int64(p.KeepaliveRetries)),
		DeadPeerDetection: types.Int64Value(int64(p.DeadPeerDetection)),
		RekeyInterval:     types.Int64Value(int64(p.RekeyInterval)),
		LoginMessage:      types.StringValue(p.LoginMessage),
		BannerMessage:     types.StringValue(p.BannerMessage),
	}
	if p.MaxConnectionTime != nil {
		out.MaxConnectionTime = flattenRavpnMaxConnTime(p.MaxConnectionTime)
	}
	return out
}

func flattenRavpnMaxConnTime(p *ravpnprofiles.MaxConnTime) *ravpnMaxConnTimeModel {
	if p == nil {
		return nil
	}
	return &ravpnMaxConnTimeModel{
		Enabled: types.BoolValue(p.Enabled),
		Value:   types.Int64Value(int64(p.Value)),
	}
}

// --------------------------------------------------------------------------
// Error helper
// --------------------------------------------------------------------------

func ravpnHTTPErrorDetail(err error, httpResp *http.Response) string {
	if err == nil {
		return ""
	}
	detail := err.Error()
	if httpResp == nil || httpResp.Body == nil {
		return detail
	}
	body, readErr := io.ReadAll(httpResp.Body)
	if readErr == nil && len(body) > 0 {
		detail += " | body: " + string(body)
	}
	return detail
}

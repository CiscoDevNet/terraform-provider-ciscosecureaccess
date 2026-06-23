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
	"strings"
	"time"

	"github.com/CiscoDevNet/go-ciscosecureaccess/client"
	"github.com/CiscoDevNet/go-ciscosecureaccess/privateapps"
	"github.com/avast/retry-go/v4"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ resource.Resource                   = &privateResourceResource{}
	_ resource.ResourceWithConfigure      = &privateResourceResource{}
	_ resource.ResourceWithValidateConfig = &privateResourceResource{}
)

// Constants for private resource management
const (
	// Access types
	accessTypeClient  = "client"
	accessTypeNetwork = "network"
	accessTypeBrowser = "browser"

	// Browser-based access defaults
	browserProtocolHTTP   = "http"
	browserProtocolHTTPS  = "https"
	browserProtocolSSH    = "ssh"
	browserProtocolRDPTCP = "rdp-tcp"

	// HTTP status codes
	privateResourceHTTPNotFound    = 404
	privateResourceHTTPConflict    = 409
	privateResourceHTTPTooManyReqs = 429

	// Retry configuration
	retryMaxAttempts = 3
	retryBaseDelay   = time.Second * 2

	// Resource names
	privateResourceName     = "ciscosecureaccess_private_resource"
	privateResourceTestName = "test_resource"
)

// NewPrivateResourceResource is a helper function to simplify the provider implementation.
func NewPrivateResourceResource() resource.Resource {
	return &privateResourceResource{}
}

// privateResourceResource is the resource implementation.
type privateResourceResource struct {
	client privateapps.APIClient
}

// privateResourceResourceModel maps the data schema data.
type privateResourceResourceModel struct {
	ID                            types.String `tfsdk:"id"`
	Name                          types.String `tfsdk:"name"`
	AccessTypes                   types.Set    `tfsdk:"access_types"`
	Addresses                     types.Set    `tfsdk:"addresses"`
	Description                   types.String `tfsdk:"description"`
	ClientReachableAddresses      types.Set    `tfsdk:"client_reachable_addresses"`
	CertificateID                 types.Int64  `tfsdk:"certificate_id"`
	BrowserProtocol               types.String `tfsdk:"browser_protocol"`
	BrowserExternalFQDNPrefix     types.String `tfsdk:"browser_external_fqdn_prefix"`
	BrowserSNI                    types.String `tfsdk:"browser_sni"`
	BrowserSSLVerificationEnabled types.Bool   `tfsdk:"browser_ssl_verification_enabled"`
	BrowserExternalFQDN           types.String `tfsdk:"browser_external_fqdn"`
}

// ValidAccessTypes returns the valid access types for private resources
func (m privateResourceResourceModel) ValidAccessTypes() []string {
	return []string{accessTypeClient, accessTypeNetwork, accessTypeBrowser}
}

func validProtocolClientToResourceValues() []string {
	validProtocols := make([]string, 0, len(privateapps.AllowedProtocolClientToResourceEnumValues))

	for _, protocol := range privateapps.AllowedProtocolClientToResourceEnumValues {
		validProtocols = append(validProtocols, string(protocol))
	}

	return validProtocols
}

func validBrowserProtocolValues() []string {
	return []string{
		browserProtocolHTTP,
		browserProtocolHTTPS,
		browserProtocolSSH,
		browserProtocolRDPTCP,
	}
}

func expectedBrowserTrafficSelectorProtocol(browserProtocol string) string {
	switch strings.ToLower(strings.TrimSpace(browserProtocol)) {
	case browserProtocolHTTP, browserProtocolHTTPS:
		return string(privateapps.HTTP_HTTPS)
	case browserProtocolSSH:
		return string(privateapps.SSH)
	case browserProtocolRDPTCP:
		return string(privateapps.RDP_TCP)
	default:
		return ""
	}
}

func hasAccessType(ctx context.Context, accessTypesSet types.Set, accessType string) (bool, diag.Diagnostics) {
	var diags diag.Diagnostics
	if accessTypesSet.IsNull() || accessTypesSet.IsUnknown() {
		return false, diags
	}

	var accessTypes []string
	diags.Append(accessTypesSet.ElementsAs(ctx, &accessTypes, true)...)
	if diags.HasError() {
		return false, diags
	}

	for _, candidate := range accessTypes {
		if candidate == accessType {
			return true, diags
		}
	}

	return false, diags
}

// addressTypesModel represents address configuration for private resources
type addressTypesModel struct {
	Addresses       types.Set `tfsdk:"addresses"`
	TrafficSelector types.Set `tfsdk:"traffic_selector"`
}

// trafficSelectorModel represents protocol and port configuration
type trafficSelectorModel struct {
	Ports    types.String `tfsdk:"ports"`
	Protocol types.String `tfsdk:"protocol"`
}

type browserProtocolDefaultModifier struct{}

func (m browserProtocolDefaultModifier) Description(context.Context) string {
	return "Defaults browser_protocol to https when browser access is enabled."
}

func (m browserProtocolDefaultModifier) MarkdownDescription(ctx context.Context) string {
	return m.Description(ctx)
}

func (m browserProtocolDefaultModifier) PlanModifyString(ctx context.Context, req planmodifier.StringRequest, resp *planmodifier.StringResponse) {
	if req.ConfigValue.IsUnknown() {
		return
	}
	if !req.ConfigValue.IsNull() {
		return
	}

	var plan privateResourceResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	hasBrowser, diags := hasAccessType(ctx, plan.AccessTypes, accessTypeBrowser)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if hasBrowser {
		resp.PlanValue = types.StringValue(browserProtocolHTTPS)
		return
	}

	resp.PlanValue = types.StringNull()
}

type browserSSLVerificationDefaultModifier struct{}

func (m browserSSLVerificationDefaultModifier) Description(context.Context) string {
	return "Defaults browser_ssl_verification_enabled to true when browser access is enabled."
}

func (m browserSSLVerificationDefaultModifier) MarkdownDescription(ctx context.Context) string {
	return m.Description(ctx)
}

func (m browserSSLVerificationDefaultModifier) PlanModifyBool(ctx context.Context, req planmodifier.BoolRequest, resp *planmodifier.BoolResponse) {
	if req.ConfigValue.IsUnknown() {
		return
	}
	if !req.ConfigValue.IsNull() {
		return
	}

	var plan privateResourceResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	hasBrowser, diags := hasAccessType(ctx, plan.AccessTypes, accessTypeBrowser)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	if !hasBrowser {
		resp.PlanValue = types.BoolNull()
		return
	}

	resp.PlanValue = types.BoolValue(true)
}

// Metadata returns the resource type name.
func (r *privateResourceResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_private_resource"
}

// Configure adds the provider configured client to the resource.
func (r *privateResourceResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	factory, ok := req.ProviderData.(*client.SSEClientFactory)
	if !ok {
		resp.Diagnostics.AddError("Unexpected Provider Data Type",
			fmt.Sprintf("expected *client.SSEClientFactory, got %T", req.ProviderData))
		return
	}
	r.client = *factory.GetPrivateAppsClient(ctx)
	tflog.Debug(ctx, "Configured private resource client")
}

// Schema defines the schema for the resource.
func (r *privateResourceResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "Unique ID of private resource",
				Computed:    true,
				Optional:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				Description: "Name of private resource",
				Required:    true,
			},
			"access_types": schema.SetAttribute{
				Description: "Access types for private resource",
				ElementType: types.StringType,
				Required:    true,
				Validators: []validator.Set{
					setvalidator.ValueStringsAre(stringvalidator.OneOf(privateResourceResourceModel{}.ValidAccessTypes()...)),
				},
			},
			"addresses": schema.SetNestedAttribute{
				Description: "List of address/protocol pairs for the private resource",
				Optional:    true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: addressTypesModel{}.AddressTypesAttributesNested(),
				},
			},
			"description": schema.StringAttribute{
				Description: "Description of private resource",
				Optional:    true,
			},
			"certificate_id": schema.Int64Attribute{
				Description: "Object ID of certificate to use for decrypting traffic",
				Optional:    true,
			},
			"client_reachable_addresses": schema.SetAttribute{
				Description: "Addresses allowed for client-based access",
				ElementType: types.StringType,
				Optional:    true,
				// TODO: Validate "client" in types
			},
			"browser_protocol": schema.StringAttribute{
				Description: "Protocol for browser-based access from the proxy to the private resource. Defaults to https when browser access is enabled.",
				Optional:    true,
				Computed:    true,
				Validators: []validator.String{
					stringvalidator.OneOf(validBrowserProtocolValues()...),
				},
				PlanModifiers: []planmodifier.String{
					browserProtocolDefaultModifier{},
				},
			},
			"browser_external_fqdn_prefix": schema.StringAttribute{
				Description: "External FQDN prefix for browser-based access. Required when access_types includes browser.",
				Optional:    true,
			},
			"browser_sni": schema.StringAttribute{
				Description: "SNI domain name for HTTPS browser-based access.",
				Optional:    true,
			},
			"browser_ssl_verification_enabled": schema.BoolAttribute{
				Description: "Whether to enable upstream SSL verification for browser-based access. Defaults to true when browser access is enabled.",
				Optional:    true,
				Computed:    true,
				PlanModifiers: []planmodifier.Bool{
					browserSSLVerificationDefaultModifier{},
				},
			},
			"browser_external_fqdn": schema.StringAttribute{
				Description: "External FQDN for browser-based access returned by the API.",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
		},
	}
}

func (r *privateResourceResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var config privateResourceResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(validatePrivateResourcePlan(ctx, &config)...)
}

func validatePrivateResourcePlan(ctx context.Context, plan *privateResourceResourceModel) diag.Diagnostics {
	var diags diag.Diagnostics

	hasBrowser, accessDiags := hasAccessType(ctx, plan.AccessTypes, accessTypeBrowser)
	diags.Append(accessDiags...)
	if diags.HasError() || !hasBrowser {
		return diags
	}

	if plan.BrowserExternalFQDNPrefix.IsNull() || plan.BrowserExternalFQDNPrefix.IsUnknown() || strings.TrimSpace(plan.BrowserExternalFQDNPrefix.ValueString()) == "" {
		diags.AddAttributeError(
			path.Root("browser_external_fqdn_prefix"),
			"Missing Browser External FQDN Prefix",
			"browser_external_fqdn_prefix must be set when access_types includes \"browser\".",
		)
	}

	diags.Append(validateBrowserAccessPorts(ctx, plan)...)
	diags.Append(validateBrowserAccessProtocols(ctx, plan)...)
	return diags
}

func validateBrowserAccessPorts(ctx context.Context, plan *privateResourceResourceModel) diag.Diagnostics {
	var diags diag.Diagnostics
	if plan.Addresses.IsNull() || plan.Addresses.IsUnknown() {
		return diags
	}

	var addressList []addressTypesModel
	diags.Append(plan.Addresses.ElementsAs(ctx, &addressList, true)...)
	if diags.HasError() {
		return diags
	}

	for _, addressConfig := range addressList {
		if addressConfig.TrafficSelector.IsNull() || addressConfig.TrafficSelector.IsUnknown() {
			continue
		}

		var selectors []trafficSelectorModel
		diags.Append(addressConfig.TrafficSelector.ElementsAs(ctx, &selectors, true)...)
		if diags.HasError() {
			return diags
		}

		for _, selector := range selectors {
			if selector.Ports.IsNull() || selector.Ports.IsUnknown() || strings.TrimSpace(selector.Ports.ValueString()) == "" {
				diags.AddAttributeError(
					path.Root("addresses"),
					"Missing Browser Access Port",
					"Browser-based access requires traffic selector ports to be 80, 443, or both.",
				)
				continue
			}

			for _, port := range strings.Split(selector.Ports.ValueString(), ",") {
				port = strings.TrimSpace(port)
				if port != "80" && port != "443" {
					diags.AddAttributeError(
						path.Root("addresses"),
						"Invalid Browser Access Port",
						fmt.Sprintf("Browser-based access only supports ports 80 and 443. Found %q.", selector.Ports.ValueString()),
					)
					break
				}
			}
		}
	}

	return diags
}

func validateBrowserAccessProtocols(ctx context.Context, plan *privateResourceResourceModel) diag.Diagnostics {
	var diags diag.Diagnostics
	if plan.Addresses.IsNull() || plan.Addresses.IsUnknown() {
		return diags
	}

	var addressList []addressTypesModel
	diags.Append(plan.Addresses.ElementsAs(ctx, &addressList, true)...)
	if diags.HasError() {
		return diags
	}

	browserProtocol := browserProtocolHTTPS
	if !plan.BrowserProtocol.IsNull() && !plan.BrowserProtocol.IsUnknown() {
		browserProtocol = plan.BrowserProtocol.ValueString()
	}

	expectedProtocol := expectedBrowserTrafficSelectorProtocol(browserProtocol)
	if expectedProtocol == "" {
		return diags
	}

	for _, addressConfig := range addressList {
		if addressConfig.TrafficSelector.IsNull() || addressConfig.TrafficSelector.IsUnknown() {
			continue
		}

		var selectors []trafficSelectorModel
		diags.Append(addressConfig.TrafficSelector.ElementsAs(ctx, &selectors, true)...)
		if diags.HasError() {
			return diags
		}

		for _, selector := range selectors {
			if selector.Protocol.IsNull() || selector.Protocol.IsUnknown() || strings.TrimSpace(selector.Protocol.ValueString()) == "" {
				diags.AddAttributeError(
					path.Root("addresses"),
					"Missing Browser Access Protocol",
					fmt.Sprintf("Browser-based access with browser_protocol %q requires traffic selector protocol %q.", browserProtocol, expectedProtocol),
				)
				continue
			}

			protocol := strings.TrimSpace(selector.Protocol.ValueString())
			if protocol != expectedProtocol {
				diags.AddAttributeError(
					path.Root("addresses"),
					"Invalid Browser Access Protocol",
					fmt.Sprintf("Browser-based access with browser_protocol %q requires traffic selector protocol %q. Found %q.", browserProtocol, expectedProtocol, protocol),
				)
			}
		}
	}

	return diags
}

func (a addressTypesModel) AddressTypesAttributesNested() map[string]schema.Attribute {
	return map[string]schema.Attribute{
		"addresses": schema.SetAttribute{
			Description: "One list of addresses for the private resource",
			ElementType: types.StringType,
			Optional:    true,
		},
		"traffic_selector": schema.SetNestedAttribute{
			Description: "Protocol/port pairs for this list of addresses",
			Optional:    true,
			NestedObject: schema.NestedAttributeObject{
				Attributes: trafficSelectorModel{}.TrafficSelectorAttributesNested(),
			},
		},
	}
}

func (a addressTypesModel) AttrTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"traffic_selector": types.SetType{ElemType: types.ObjectType{AttrTypes: trafficSelectorModel{}.AttrTypes()}},
		"addresses":        types.SetType{ElemType: types.StringType},
	}
}

func (t trafficSelectorModel) TrafficSelectorAttributesNested() map[string]schema.Attribute {
	return map[string]schema.Attribute{
		"ports": schema.StringAttribute{
			Description: "Port numbers for this traffic selector",
			Optional:    true,
		},
		"protocol": schema.StringAttribute{
			Description: "Protocols for this traffic selector",
			Optional:    true,
			Validators: []validator.String{
				stringvalidator.OneOf(validProtocolClientToResourceValues()...),
			},
		},
	}
}

func (t trafficSelectorModel) AttrTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"ports":    types.StringType,
		"protocol": types.StringType,
	}
}

// formatCreatePrivateResourceRequest converts the Terraform plan into an API request
func formatCreatePrivateResourceRequest(ctx context.Context, plan *privateResourceResourceModel) (*privateapps.PrivateResourceRequest, diag.Diagnostics) {
	var diags diag.Diagnostics

	tflog.Debug(ctx, "Formatting private resource create request", map[string]interface{}{
		"resource_name": plan.Name.ValueString(),
	})

	// Parse access types from plan
	accessTypesInner, accessDiags := parseAccessTypes(ctx, plan)
	if accessDiags.HasError() {
		diags.Append(accessDiags...)
		return nil, diags
	}

	// Parse addresses from plan
	addressesInner, addressDiags := parseAddresses(ctx, plan)
	if addressDiags.HasError() {
		diags.Append(addressDiags...)
		return nil, diags
	}

	// Create the request
	name := plan.Name.ValueString()
	description := plan.Description.ValueString()

	request := privateapps.NewPrivateResourceRequest(name, accessTypesInner, addressesInner)
	request.SetDescription(description)

	if !plan.CertificateID.IsNull() {
		request.SetCertificateId(plan.CertificateID.ValueInt64())
		tflog.Debug(ctx, "Setting certificate ID", map[string]interface{}{
			"certificate_id": plan.CertificateID.ValueInt64(),
		})
	}

	tflog.Debug(ctx, "Successfully formatted private resource create request")
	return request, diags
}

// parseAccessTypes extracts and converts access types from the plan
func parseAccessTypes(ctx context.Context, plan *privateResourceResourceModel) ([]privateapps.AccessTypesRequestInner, diag.Diagnostics) {
	var diags diag.Diagnostics
	var accessTypes []string

	plan.AccessTypes.ElementsAs(ctx, &accessTypes, true)
	accessTypesInner := make([]privateapps.AccessTypesRequestInner, len(accessTypes))

	for i, accessType := range accessTypes {
		typeObject := privateapps.AccessTypesRequestInner{}

		switch accessType {
		case accessTypeNetwork:
			typeObject.NetworkBasedAccess = &privateapps.NetworkBasedAccess{Type: accessTypeNetwork}
			tflog.Debug(ctx, "Configured network-based access")

		case accessTypeClient:
			var addresses []string
			clientDiags := plan.ClientReachableAddresses.ElementsAs(ctx, &addresses, true)
			if clientDiags.HasError() {
				tflog.Error(ctx, "Cannot deserialize client_reachable_addresses")
				diags.Append(clientDiags...)
				return nil, diags
			}
			typeObject.ClientBasedAccess = &privateapps.ClientBasedAccess{
				Type:               accessTypeClient,
				ReachableAddresses: addresses,
			}
			tflog.Debug(ctx, "Configured client-based access", map[string]interface{}{
				"reachable_addresses_count": len(addresses),
			})

		case accessTypeBrowser:
			protocol := privateapps.ProtocolProxyToResource(browserProtocolHTTPS)
			if !plan.BrowserProtocol.IsNull() && !plan.BrowserProtocol.IsUnknown() {
				protocol = privateapps.ProtocolProxyToResource(plan.BrowserProtocol.ValueString())
			}

			browserAccess := privateapps.NewBrowserBasedAccessRequest(accessTypeBrowser, protocol)
			if plan.BrowserExternalFQDNPrefix.IsNull() || plan.BrowserExternalFQDNPrefix.IsUnknown() || strings.TrimSpace(plan.BrowserExternalFQDNPrefix.ValueString()) == "" {
				diags.AddAttributeError(
					path.Root("browser_external_fqdn_prefix"),
					"Missing Browser External FQDN Prefix",
					"browser_external_fqdn_prefix must be set when access_types includes \"browser\".",
				)
				return nil, diags
			}
			browserAccess.SetExternalFQDNPrefix(plan.BrowserExternalFQDNPrefix.ValueString())

			if !plan.BrowserSNI.IsNull() && !plan.BrowserSNI.IsUnknown() && strings.TrimSpace(plan.BrowserSNI.ValueString()) != "" {
				browserAccess.SetSni(plan.BrowserSNI.ValueString())
			}

			if !plan.BrowserSSLVerificationEnabled.IsNull() && !plan.BrowserSSLVerificationEnabled.IsUnknown() {
				browserAccess.SetSslVerificationEnabled(plan.BrowserSSLVerificationEnabled.ValueBool())
			} else if protocol == privateapps.ProtocolProxyToResource(browserProtocolHTTPS) {
				browserAccess.SetSslVerificationEnabled(true)
			}

			typeObject.BrowserBasedAccessRequest = browserAccess
			tflog.Debug(ctx, "Configured browser-based access", map[string]interface{}{
				"protocol": string(protocol),
			})
		}

		accessTypesInner[i] = typeObject
	}

	return accessTypesInner, diags
}

// parseAddresses extracts and converts address configurations from the plan
func parseAddresses(ctx context.Context, plan *privateResourceResourceModel) ([]privateapps.ResourceAddressesInner, diag.Diagnostics) {
	var diags diag.Diagnostics
	var addressList []addressTypesModel

	addressDiags := plan.Addresses.ElementsAs(ctx, &addressList, true)
	if addressDiags.HasError() {
		diags.Append(addressDiags...)
		return nil, diags
	}

	tflog.Debug(ctx, "Processing address configurations", map[string]interface{}{
		"address_count": len(addressList),
	})

	addressesInner := make([]privateapps.ResourceAddressesInner, len(addressList))

	for i, addressConfig := range addressList {
		tflog.Debug(ctx, "Processing address configuration", map[string]interface{}{
			"address_index": i,
		})

		// Parse traffic selectors
		protocolPortsInner, trafficDiags := parseTrafficSelectors(ctx, &addressConfig)
		if trafficDiags.HasError() {
			diags.Append(trafficDiags...)
			return nil, diags
		}

		// Parse IP addresses
		var ips []string
		addressConfig.Addresses.ElementsAs(ctx, &ips, true)

		addressesInner[i] = privateapps.ResourceAddressesInner{
			DestinationAddr: ips,
			ProtocolPorts:   protocolPortsInner,
		}

		tflog.Debug(ctx, "Configured address entry", map[string]interface{}{
			"destination_addresses": ips,
			"protocol_ports_count":  len(protocolPortsInner),
		})
	}

	return addressesInner, diags
}

// parseTrafficSelectors extracts and converts traffic selector configurations
func parseTrafficSelectors(ctx context.Context, addressConfig *addressTypesModel) ([]privateapps.ResourceAddressesInnerProtocolPortsInner, diag.Diagnostics) {
	var diags diag.Diagnostics
	var protocolPortsList []trafficSelectorModel

	addressConfig.TrafficSelector.ElementsAs(ctx, &protocolPortsList, true)
	protocolPortsInner := make([]privateapps.ResourceAddressesInnerProtocolPortsInner, len(protocolPortsList))

	for k, selector := range protocolPortsList {
		ports := selector.Ports.ValueString()
		protocol := privateapps.ProtocolClientToResource(selector.Protocol.ValueString())

		protocolPortsInner[k] = privateapps.ResourceAddressesInnerProtocolPortsInner{
			Protocol: &protocol,
			Ports:    &ports,
		}

		tflog.Debug(ctx, "Configured traffic selector", map[string]interface{}{
			"protocol": string(protocol),
			"ports":    ports,
		})
	}

	return protocolPortsInner, diags
}

// Create creates the resource and sets the initial Terraform state.
func (r *privateResourceResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	// Retrieve values from plan
	var plan privateResourceResourceModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Info(ctx, "Creating private resource", map[string]interface{}{
		"resource_name": plan.Name.ValueString(),
	})

	// Format the create request
	resourceDefinition, diags := formatCreatePrivateResourceRequest(ctx, &plan)
	if diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}

	// Create the resource with retry logic
	createResp, err := r.createPrivateResourceWithRetry(ctx, resourceDefinition)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error creating private resource",
			fmt.Sprintf("Failed to create private resource %s: %v", plan.Name.ValueString(), err),
		)
		return
	}

	// Set the resource ID
	resourceID := createResp.GetResourceId()
	plan.ID = types.StringValue(strconv.Itoa(int(resourceID)))
	readDiags := r.readPrivateResourceIntoState(ctx, resourceID, &plan)
	resp.Diagnostics.Append(readDiags...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Info(ctx, "Successfully created private resource", map[string]interface{}{
		"resource_id":   resourceID,
		"resource_name": plan.Name.ValueString(),
	})

	// Set state to fully populated data
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

// createPrivateResourceWithRetry creates a private resource with retry logic for handling conflicts
func (r *privateResourceResource) createPrivateResourceWithRetry(ctx context.Context, resourceDefinition *privateapps.PrivateResourceRequest) (*privateapps.PrivateResourceResponse, error) {
	var createResp *privateapps.PrivateResourceResponse
	var err error

	err = retry.Do(
		func() error {
			var httpRes *http.Response
			createResp, httpRes, err = r.client.PrivateResourcesAPI.AddPrivateResource(ctx).PrivateResourceRequest(*resourceDefinition).Execute()

			if err != nil {
				if httpRes != nil {
					bodyBytes, _ := io.ReadAll(httpRes.Body)
					statusCode := httpRes.StatusCode

					tflog.Debug(ctx, "Private resource creation attempt failed", map[string]interface{}{
						"status_code":   statusCode,
						"response_body": string(bodyBytes),
						"error":         err.Error(),
					})

					if statusCode == privateResourceHTTPConflict || statusCode == privateResourceHTTPTooManyReqs {
						// Retryable errors
						return fmt.Errorf("retryable error (status %d): %v - %s", statusCode, err, string(bodyBytes))
					} else {
						// Non-retryable errors
						tflog.Error(ctx, "Non-retryable error creating private resource", map[string]interface{}{
							"status_code":   statusCode,
							"response_body": string(bodyBytes),
							"error":         err.Error(),
						})
						return retry.Unrecoverable(fmt.Errorf("status %d: %v - %s", statusCode, err, string(bodyBytes)))
					}
				} else {
					// HTTP response is nil
					tflog.Error(ctx, "Error creating private resource with nil HTTP response", map[string]interface{}{
						"error": err.Error(),
					})
					return retry.Unrecoverable(fmt.Errorf("HTTP response is nil: %v", err))
				}
			}

			tflog.Debug(ctx, "Private resource creation successful", map[string]interface{}{
				"resource_id": createResp.GetResourceId(),
			})
			return nil
		},
		retry.Attempts(retryMaxAttempts),
		retry.Delay(retryBaseDelay),
		retry.Context(ctx),
	)

	return createResp, err
}

func (r *privateResourceResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	// Get current state
	var state privateResourceResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	policyId, idErr := strconv.Atoi(state.ID.ValueString())
	if idErr != nil {
		resp.Diagnostics.AddError(
			"Invalid resource ID",
			fmt.Sprintf("Could not parse resource ID %q: %s", state.ID.ValueString(), idErr),
		)
		return
	}
	tflog.Debug(ctx, "Retrieving upstream policy", map[string]interface{}{
		"policy_id": policyId,
	})

	readResp, httpRes, err := r.client.PrivateResourcesAPI.GetPrivateResource(ctx, int64(policyId)).Execute()
	if err != nil {
		if httpRes != nil && httpRes.StatusCode == privateResourceHTTPNotFound {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError(
			"Error reading private resource",
			fmt.Sprintf("Cannot read private resource ID %d: %v", policyId, err),
		)
		return
	}
	tflog.Debug(ctx, "HTTP response received", map[string]interface{}{
		"status_code": httpRes.StatusCode,
		"policy_id":   policyId,
	})
	stringResp, _ := json.Marshal(readResp)
	tflog.Debug(ctx, "Definition of upstream private resource", map[string]interface{}{
		"response": string(stringResp),
	})

	resp.Diagnostics.Append(r.applyPrivateResourceResponseToState(ctx, readResp, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Set state to fully populated data
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *privateResourceResource) applyPrivateResourceResponseToState(ctx context.Context, readResp *privateapps.PrivateResourceResponse, state *privateResourceResourceModel) diag.Diagnostics {
	var diags diag.Diagnostics
	if readResp == nil {
		diags.AddError("Private resource response is nil", "Cannot update Terraform state from an empty private resource response.")
		return diags
	}

	if readResp.Name != nil {
		state.Name = types.StringValue(*readResp.Name)
	}
	if readResp.Description != nil {
		state.Description = types.StringValue(*readResp.Description)
	} else {
		state.Description = types.StringNull()
	}
	if readResp.CertificateId != nil {
		state.CertificateID = types.Int64Value(*readResp.CertificateId)
	} else {
		state.CertificateID = types.Int64Null()
	}

	addressUpdates, addressDiags := r.processReadAddresses(ctx, readResp.ResourceAddresses)
	if addressDiags.HasError() {
		diags.Append(addressDiags...)
		return diags
	}

	accessTypesDiags := r.processReadAccessTypes(ctx, readResp.AccessTypes, state)
	if accessTypesDiags.HasError() {
		diags.Append(accessTypesDiags...)
		return diags
	}

	var respDiags diag.Diagnostics
	state.Addresses, respDiags = types.SetValueFrom(ctx, types.ObjectType{AttrTypes: addressTypesModel{}.AttrTypes()}, addressUpdates)
	diags.Append(respDiags...)

	return diags
}

func (r *privateResourceResource) readPrivateResourceIntoState(ctx context.Context, id int64, state *privateResourceResourceModel) diag.Diagnostics {
	var diags diag.Diagnostics

	var readResp *privateapps.PrivateResourceResponse
	err := retry.Do(
		func() error {
			var httpRes *http.Response
			var err error
			readResp, httpRes, err = r.client.PrivateResourcesAPI.GetPrivateResource(ctx, id).Execute()
			if err != nil {
				if httpRes != nil && httpRes.StatusCode == privateResourceHTTPNotFound {
					return fmt.Errorf("private resource %d not found after mutation", id)
				}
				return retry.Unrecoverable(fmt.Errorf("failed to read private resource %d after mutation: %w", id, err))
			}

			return nil
		},
		retry.Attempts(retryMaxAttempts),
		retry.Delay(retryBaseDelay),
		retry.Context(ctx),
	)
	if err != nil {
		diags.AddError(
			"Error reading private resource after mutation",
			err.Error(),
		)
		return diags
	}

	diags.Append(r.applyPrivateResourceResponseToState(ctx, readResp, state)...)
	return diags
}

// processReadAddresses converts API address response to internal model
func (r *privateResourceResource) processReadAddresses(ctx context.Context, apiAddresses []privateapps.ResourceAddressesInner) ([]addressTypesModel, diag.Diagnostics) {
	var diags diag.Diagnostics
	var addressUpdates []addressTypesModel

	for i, resourceAddress := range apiAddresses {
		protocolPortsList := apiAddresses[i].ProtocolPorts
		protocolPortsInner := make([]trafficSelectorModel, len(protocolPortsList))

		for k := range protocolPortsList {
			ports := protocolPortsList[k].GetPorts()
			protocol := protocolPortsList[k].GetProtocol()
			protocolPortsInner[k] = trafficSelectorModel{
				Protocol: types.StringValue(string(protocol)),
				Ports:    types.StringValue(ports),
			}
		}

		var addressUpdate addressTypesModel
		var addrDiags diag.Diagnostics
		addressUpdate.Addresses, addrDiags = types.SetValueFrom(ctx, types.StringType, resourceAddress.DestinationAddr)
		if addrDiags.HasError() {
			return nil, addrDiags
		}
		addressUpdate.TrafficSelector, diags = types.SetValueFrom(ctx, types.ObjectType{AttrTypes: trafficSelectorModel{}.AttrTypes()}, protocolPortsInner)
		if diags.HasError() {
			return nil, diags
		}

		tflog.Debug(ctx, "Processed address configuration", map[string]interface{}{
			"address_index": i,
		})
		addressUpdates = append(addressUpdates, addressUpdate)
	}

	return addressUpdates, diags
}

// processReadAccessTypes processes access types from API response and updates state
func (r *privateResourceResource) processReadAccessTypes(ctx context.Context, apiAccessTypes []privateapps.AccessTypesInner, state *privateResourceResourceModel) diag.Diagnostics {
	var diags diag.Diagnostics

	respString, _ := json.Marshal(apiAccessTypes)
	tflog.Debug(ctx, "Private resource access types response", map[string]interface{}{
		"access_types": string(respString),
	})

	var clientTypeMissing bool = true
	var browserTypeMissing bool = true

	// We need to use type assertion or reflection to handle the API response
	// For now, let's use the original approach but with better logging
	for _, access := range apiAccessTypes {
		accessBytes, _ := json.Marshal(access)
		tflog.Debug(ctx, "Processing access type", map[string]interface{}{
			"access_type": string(accessBytes),
		})

		// Process access type based on structure
		if access.BranchAccess != nil {
			tflog.Debug(ctx, "Found branch access configuration")
		}

		if access.ClientBasedAccess != nil {
			clientTypeMissing = false
			tflog.Debug(ctx, "Processing client-based access addresses")

			var clientDiags diag.Diagnostics
			state.ClientReachableAddresses, clientDiags = types.SetValueFrom(ctx, types.StringType, access.ClientBasedAccess.ReachableAddresses)
			if clientDiags.HasError() {
				diags.Append(clientDiags...)
				return diags
			}
		}

		if access.BrowserBasedAccessResponse != nil {
			browserTypeMissing = false
			tflog.Debug(ctx, "Processing browser-based access configuration")

			state.BrowserProtocol = types.StringValue(string(access.BrowserBasedAccessResponse.Protocol))
			if access.BrowserBasedAccessResponse.Sni != nil {
				state.BrowserSNI = types.StringValue(*access.BrowserBasedAccessResponse.Sni)
			} else {
				state.BrowserSNI = types.StringNull()
			}
			if access.BrowserBasedAccessResponse.SslVerificationEnabled != nil {
				state.BrowserSSLVerificationEnabled = types.BoolValue(*access.BrowserBasedAccessResponse.SslVerificationEnabled)
			} else {
				state.BrowserSSLVerificationEnabled = types.BoolNull()
			}
			if access.BrowserBasedAccessResponse.ExternalFQDN != nil {
				state.BrowserExternalFQDN = types.StringValue(*access.BrowserBasedAccessResponse.ExternalFQDN)
			} else {
				state.BrowserExternalFQDN = types.StringNull()
			}
		}
	}

	if clientTypeMissing {
		state.ClientReachableAddresses = types.SetNull(types.StringType)
		tflog.Debug(ctx, "No client-based access found, setting null")
	}
	if browserTypeMissing {
		stateHasBrowser, stateDiags := hasAccessType(ctx, state.AccessTypes, accessTypeBrowser)
		if stateDiags.HasError() {
			diags.Append(stateDiags...)
			return diags
		}

		if stateHasBrowser {
			if state.BrowserProtocol.IsNull() || state.BrowserProtocol.IsUnknown() {
				state.BrowserProtocol = types.StringValue(browserProtocolHTTPS)
			}
			if state.BrowserSSLVerificationEnabled.IsNull() || state.BrowserSSLVerificationEnabled.IsUnknown() {
				state.BrowserSSLVerificationEnabled = types.BoolValue(true)
			}
			if state.BrowserExternalFQDN.IsUnknown() {
				state.BrowserExternalFQDN = types.StringNull()
			}
			tflog.Debug(ctx, "Browser-based access not returned by API, preserving configured browser state")
		} else {
			state.BrowserProtocol = types.StringNull()
			state.BrowserSNI = types.StringNull()
			state.BrowserSSLVerificationEnabled = types.BoolNull()
			state.BrowserExternalFQDN = types.StringNull()
			tflog.Debug(ctx, "No browser-based access found, setting null")
		}
	}

	return diags
}

func (r *privateResourceResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	// Retrieve values from plan and state
	var plan, state privateResourceResourceModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	diags = req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Info(ctx, "Updating private resource", map[string]interface{}{
		"resource_id":   plan.ID.ValueString(),
		"resource_name": plan.Name.ValueString(),
	})

	// Check if any updates are needed
	if r.hasResourceChanges(plan, state) {
		if err := r.updatePrivateResource(ctx, &plan, &resp.Diagnostics); err != nil {
			resp.Diagnostics.AddError(
				"Error updating private resource",
				fmt.Sprintf("Failed to update private resource %s: %v", plan.ID.ValueString(), err),
			)
			return
		}
		if resp.Diagnostics.HasError() {
			return
		}
	} else {
		tflog.Debug(ctx, "No changes detected, skipping update")
		// Write current server-truth state, not plan, to avoid drift
		resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
		return
	}

	// Set state to fully populated data (read-back already populated plan via readPrivateResourceIntoState)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// hasResourceChanges checks if the resource has any changes that require an update
func (r *privateResourceResource) hasResourceChanges(plan, state privateResourceResourceModel) bool {
	return !plan.Name.Equal(state.Name) ||
		!plan.Description.Equal(state.Description) ||
		!plan.AccessTypes.Equal(state.AccessTypes) ||
		!plan.Addresses.Equal(state.Addresses) ||
		!plan.ClientReachableAddresses.Equal(state.ClientReachableAddresses) ||
		!plan.CertificateID.Equal(state.CertificateID) ||
		!plan.BrowserProtocol.Equal(state.BrowserProtocol) ||
		!plan.BrowserExternalFQDNPrefix.Equal(state.BrowserExternalFQDNPrefix) ||
		!plan.BrowserSNI.Equal(state.BrowserSNI) ||
		!plan.BrowserSSLVerificationEnabled.Equal(state.BrowserSSLVerificationEnabled)
}

// updatePrivateResource performs the actual resource update
func (r *privateResourceResource) updatePrivateResource(ctx context.Context, plan *privateResourceResourceModel, diagnostics *diag.Diagnostics) error {
	baseline, diags := formatCreatePrivateResourceRequest(ctx, plan)
	if diags.HasError() {
		diagnostics.Append(diags...)
		return fmt.Errorf("failed to format update request")
	}

	payload := privateapps.NewPrivateResourceRequest(baseline.Name, baseline.AccessTypes, baseline.ResourceAddresses)
	payload.Description = baseline.Description
	if baseline.CertificateId != nil {
		payload.SetCertificateId(*baseline.CertificateId)
	}

	id, idErr := strconv.Atoi(plan.ID.ValueString())
	if idErr != nil {
		return fmt.Errorf("invalid resource ID %q: %w", plan.ID.ValueString(), idErr)
	}
	updateResp, _, err := r.client.PrivateResourcesAPI.PutPrivateResource(ctx, int64(id)).PrivateResourceRequest(*payload).Execute()

	if err != nil {
		return fmt.Errorf("API call failed: %w", err)
	}

	updateString, _ := json.Marshal(updateResp)
	tflog.Debug(ctx, "Update private resource response", map[string]interface{}{
		"response": string(updateString),
	})

	diagnostics.Append(r.readPrivateResourceIntoState(ctx, int64(id), plan)...)
	if diagnostics.HasError() {
		return nil
	}

	tflog.Info(ctx, "Successfully updated private resource", map[string]interface{}{
		"resource_id": plan.ID.ValueString(),
	})

	return nil
}

// Delete deletes the resource and removes the Terraform state on success.
func (r *privateResourceResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	// Retrieve values from state
	var state privateResourceResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	id, idErr := strconv.Atoi(state.ID.ValueString())
	if idErr != nil {
		resp.Diagnostics.AddError(
			"Invalid resource ID",
			fmt.Sprintf("Could not parse resource ID %q: %s", state.ID.ValueString(), idErr),
		)
		return
	}
	tflog.Info(ctx, "Deleting private resource", map[string]interface{}{
		"resource_id": id,
	})

	// Delete existing private resource
	delResp, httpRes, err := r.client.PrivateResourcesAPI.DeletePrivateResource(ctx, int64(id)).Execute()
	if err != nil {
		if httpRes != nil && httpRes.StatusCode == privateResourceHTTPNotFound {
			tflog.Debug(ctx, "Private resource not found, already deleted")
			return
		}
		var httpRespDetails string
		if httpRes != nil {
			httpRespDetails = fmt.Sprintf("HTTP response status: %d", httpRes.StatusCode)
		} else {
			httpRespDetails = "HTTP response: <nil>"
		}
		resp.Diagnostics.AddError(
			"Error deleting private resource",
			fmt.Sprintf("Could not delete private resource ID %d: %v\n%v", id, err, httpRespDetails),
		)
		return
	}

	stringResp, _ := json.Marshal(delResp)
	tflog.Debug(ctx, "Private resource deletion response", map[string]interface{}{
		"response": string(stringResp),
	})

}

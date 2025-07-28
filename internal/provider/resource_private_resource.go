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
	"time"

	"github.com/CiscoDevNet/go-ciscosecureaccess/client"
	"github.com/CiscoDevNet/go-ciscosecureaccess/privateapps"
	"github.com/avast/retry-go/v4"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
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
	_ resource.Resource              = &privateResourceResource{}
	_ resource.ResourceWithConfigure = &privateResourceResource{}
)

// Constants for private resource management
const (
	// Access types
	accessTypeClient  = "client"
	accessTypeNetwork = "network"

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
	ID                       types.String `tfsdk:"id"`
	Name                     types.String `tfsdk:"name"`
	AccessTypes              types.Set    `tfsdk:"access_types"`
	Addresses                types.Set    `tfsdk:"addresses"`
	Description              types.String `tfsdk:"description"`
	ClientReachableAddresses types.Set    `tfsdk:"client_reachable_addresses"`
	CertificateID            types.Int64  `tfsdk:"certificate_id"`
}

// ValidAccessTypes returns the valid access types for private resources
func (m privateResourceResourceModel) ValidAccessTypes() []string {
	return []string{accessTypeClient, accessTypeNetwork}
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

// Metadata returns the resource type name.
func (r *privateResourceResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_private_resource"
}

// Configure adds the provider configured client to the resource.
func (r *privateResourceResource) Configure(ctx context.Context, req resource.ConfigureRequest, _ *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	r.client = *req.ProviderData.(*client.SSEClientFactory).GetPrivateAppsClient(ctx)
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
		},
	}
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

	policyId, _ := strconv.Atoi(state.ID.ValueString())
	tflog.Debug(ctx, "Retrieving upstream policy", map[string]interface{}{
		"policy_id": policyId,
	})

	readResp, httpRes, err := r.client.PrivateResourcesAPI.GetPrivateResource(ctx, int64(policyId)).Execute()
	tflog.Debug(ctx, "HTTP response received", map[string]interface{}{
		"status_code": httpRes.StatusCode,
		"policy_id":   policyId,
	})
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
	stringResp, _ := json.Marshal(readResp)
	tflog.Debug(ctx, "Definition of upstream private resource", map[string]interface{}{
		"response": string(stringResp),
	})

	state.Name = types.StringValue(*readResp.Name)
	state.Description = types.StringValue(*readResp.Description)

	// Process addresses
	addressUpdates, addressDiags := r.processReadAddresses(ctx, readResp.ResourceAddresses)
	if addressDiags.HasError() {
		resp.Diagnostics.Append(addressDiags...)
		return
	}

	// Process access types
	accessTypesDiags := r.processReadAccessTypes(ctx, readResp.AccessTypes, &state)
	if accessTypesDiags.HasError() {
		resp.Diagnostics.Append(accessTypesDiags...)
		return
	}

	var respDiags diag.Diagnostics
	state.Addresses, respDiags = types.SetValueFrom(ctx, types.ObjectType{AttrTypes: addressTypesModel{}.AttrTypes()}, addressUpdates)
	resp.Diagnostics.Append(respDiags...)

	// Set state to fully populated data
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
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
		addressUpdate.Addresses, _ = types.SetValueFrom(ctx, types.StringType, resourceAddress.DestinationAddr)
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
func (r *privateResourceResource) processReadAccessTypes(ctx context.Context, apiAccessTypes interface{}, state *privateResourceResourceModel) diag.Diagnostics {
	var diags diag.Diagnostics

	respString, _ := json.Marshal(apiAccessTypes)
	tflog.Debug(ctx, "Private resource access types response", map[string]interface{}{
		"access_types": string(respString),
	})

	var clientTypeMissing bool = true

	// We need to use type assertion or reflection to handle the API response
	// For now, let's use the original approach but with better logging
	switch accessTypes := apiAccessTypes.(type) {
	case []interface{}:
		for _, access := range accessTypes {
			accessBytes, _ := json.Marshal(access)
			tflog.Debug(ctx, "Processing access type", map[string]interface{}{
				"access_type": string(accessBytes),
			})

			// Process access type based on structure
			if accessMap, ok := access.(map[string]interface{}); ok {
				if _, hasBranch := accessMap["BranchAccess"]; hasBranch {
					tflog.Debug(ctx, "Found branch access configuration")
				}

				if clientAccess, hasClient := accessMap["ClientBasedAccess"]; hasClient && clientAccess != nil {
					clientTypeMissing = false
					tflog.Debug(ctx, "Processing client-based access addresses")

					if clientMap, ok := clientAccess.(map[string]interface{}); ok {
						if addresses, hasAddresses := clientMap["ReachableAddresses"]; hasAddresses {
							if addressSlice, ok := addresses.([]interface{}); ok {
								stringAddresses := make([]string, len(addressSlice))
								for i, addr := range addressSlice {
									if addrStr, ok := addr.(string); ok {
										stringAddresses[i] = addrStr
									}
								}

								var clientDiags diag.Diagnostics
								state.ClientReachableAddresses, clientDiags = types.SetValueFrom(ctx, types.StringType, stringAddresses)
								if clientDiags.HasError() {
									diags.Append(clientDiags...)
									return diags
								}
							}
						}
					}
				}
			}
		}
	}

	if clientTypeMissing {
		state.ClientReachableAddresses = types.SetNull(types.StringType)
		tflog.Debug(ctx, "No client-based access found, setting null")
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
	} else {
		tflog.Debug(ctx, "No changes detected, skipping update")
	}

	// Set state to fully populated data
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// hasResourceChanges checks if the resource has any changes that require an update
func (r *privateResourceResource) hasResourceChanges(plan, state privateResourceResourceModel) bool {
	return !plan.Name.Equal(state.Name) ||
		!plan.Description.Equal(state.Description) ||
		!plan.AccessTypes.Equal(state.AccessTypes) ||
		!plan.Addresses.Equal(state.Addresses) ||
		!plan.CertificateID.Equal(state.CertificateID)
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

	id, _ := strconv.Atoi(plan.ID.ValueString())
	updateResp, _, err := r.client.PrivateResourcesAPI.PutPrivateResource(ctx, int64(id)).PrivateResourceRequest(*payload).Execute()

	if err != nil {
		return fmt.Errorf("API call failed: %w", err)
	}

	updateString, _ := json.Marshal(updateResp)
	tflog.Debug(ctx, "Update private resource response", map[string]interface{}{
		"response": string(updateString),
	})

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

	id, _ := strconv.Atoi(state.ID.ValueString())
	tflog.Info(ctx, "Deleting private resource", map[string]interface{}{
		"resource_id": id,
	})

	// Delete existing private resource
	delResp, httpRes, err := r.client.PrivateResourcesAPI.DeletePrivateResource(ctx, int64(id)).Execute()
	if httpRes.StatusCode == privateResourceHTTPNotFound {
		tflog.Debug(ctx, "Private resource not found, already deleted")
		return
	}
	if err != nil {
		resp.Diagnostics.AddError(
			"Error deleting private resource",
			fmt.Sprintf("Could not delete private resource ID %d: %v", id, err),
		)
		return
	}

	stringResp, _ := json.Marshal(delResp)
	tflog.Debug(ctx, "Private resource deletion response", map[string]interface{}{
		"response": string(stringResp),
	})

}

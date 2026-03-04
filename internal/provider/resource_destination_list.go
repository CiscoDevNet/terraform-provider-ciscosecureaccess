// Copyright 2025 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/CiscoDevNet/go-ciscosecureaccess/client"
	"github.com/CiscoDevNet/go-ciscosecureaccess/destinationlists"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var _ resource.Resource = (*destinationListResource)(nil)
var _ resource.ResourceWithValidateConfig = (*destinationListResource)(nil)

// Constants for destination list resource
const (
	// Bundle type ID for destination lists
	defaultBundleTypeID = 2
	// Maximum destinations per create API request
	maxDestinationsPerRequest = 500
	// Number of destination records to request per page
	defaultDestinationsPageLimit = 100
	// HTTP status codes
	httpStatusOK       = 200
	httpStatusNotFound = 404
	// Error messages
	destinationListNotFoundError = "\"statusCode\":404,\"error\":\"Not Found\""
)

var domainLabelRegex = regexp.MustCompile(`^[a-zA-Z0-9-]+$`)

// NewDestinationListResource creates a new destination list resource
func NewDestinationListResource() resource.Resource {
	return &destinationListResource{}
}

type destinationListResource struct {
	client destinationlists.APIClient
}

type destinationListResourceModel struct {
	Id           types.Int64  `tfsdk:"id"`
	Name         types.String `tfsdk:"name"`
	Destinations types.Set    `tfsdk:"destinations"`
}

// GetDestinations retrieves destinations for a destination list
func (r *destinationListResourceModel) GetDestinations(ctx context.Context, client *destinationlists.APIClient) ([]destinationModel, error) {
	page := int64(1)
	limit := int64(defaultDestinationsPageLimit)
	allDestinations := make([]destinationlists.DestinationObjectWithStringId, 0)

	for {
		destinationsResp, httpRes, err := client.DestinationsAPI.GetDestinations(ctx, r.Id.ValueInt64()).Page(page).Limit(limit).Execute()
		if err != nil {
			if httpRes != nil {
				return nil, fmt.Errorf("error code %s reading destinations for destination list %s: %w", httpRes.Status, r.Name.ValueString(), err)
			}
			return nil, fmt.Errorf("error reading destinations for destination list %s: %w", r.Name.ValueString(), err)
		}

		allDestinations = append(allDestinations, destinationsResp.Data...)

		total, hasTotal := destinationsResp.Meta.GetTotalOk()
		if hasTotal && int64(len(allDestinations)) >= *total {
			break
		}

		if int64(len(destinationsResp.Data)) < limit {
			break
		}

		page++
	}

	destsDebug, err := json.Marshal(allDestinations)
	if err != nil {
		return nil, fmt.Errorf("error marshaling destinations for destination list %s: %w", r.Name.ValueString(), err)
	}
	tflog.Debug(ctx, "Retrieved destinations for destination list", map[string]interface{}{
		"destination_list_id": r.Id.ValueInt64(),
		"destinations":        string(destsDebug),
	})

	modeledDestinations := make([]destinationModel, len(allDestinations))
	for i := range allDestinations {
		modeledDestinations[i] = destinationModel{
			Id:          types.StringValue(allDestinations[i].Id),
			Destination: types.StringValue(allDestinations[i].Destination),
			Type:        types.StringValue(string(allDestinations[i].Type)),
		}
		if allDestinations[i].Comment != nil {
			modeledDestinations[i].Comment = types.StringValue(*allDestinations[i].Comment)
		}
	}

	return modeledDestinations, nil
}

// UpdateDestinations updates the destinations in the resource model
func (r *destinationListResourceModel) UpdateDestinations(ctx context.Context, client *destinationlists.APIClient) diag.Diagnostics {
	var resp diag.Diagnostics
	readDestinations, err := r.GetDestinations(ctx, client)
	if err != nil {
		resp.AddError(
			fmt.Sprintf("Error retrieving destinations for %s", r.Name.ValueString()),
			fmt.Sprintf("%s", err))
		return resp
	}

	destinationListValue, diags := types.SetValueFrom(ctx, types.ObjectType{AttrTypes: destinationModel{}.AttrTypes()}, readDestinations)
	if diags.HasError() {
		resp.Append(diags...)
		return resp
	}
	r.Destinations = destinationListValue
	return resp
}

// destinationModel represents a destination in a destination list
type destinationModel struct {
	// Note: Destination.Id is a string (not int64)
	Id          types.String `tfsdk:"id"`
	Comment     types.String `tfsdk:"comment"`
	Destination types.String `tfsdk:"destination"`
	Type        types.String `tfsdk:"type"`
}

// DestinationTypes returns the allowed destination types
func (destinationModel) DestinationTypes() []string {
	destinationTypes := make([]string, len(destinationlists.AllowedModelTypeEnumValues))
	for i := range destinationlists.AllowedModelTypeEnumValues {
		destinationTypes[i] = string(destinationlists.AllowedModelTypeEnumValues[i])
	}
	return destinationTypes
}

// DestinationAttributesNested returns the nested attributes for destinations
func (d destinationModel) DestinationAttributesNested() map[string]schema.Attribute {
	return map[string]schema.Attribute{
		// (sic) Destination.Id is a string
		"id": schema.StringAttribute{
			Description: "Unique identifier for destination",
			Computed:    true,
		},
		"destination": schema.StringAttribute{
			Description: "A domain, url, or IP.",
			Required:    true,
		},
		"type": schema.StringAttribute{
			Description: "The type of the destination ('domain', 'url', 'ipv4')",
			Required:    true,
			Validators: []validator.String{
				stringvalidator.OneOf(d.DestinationTypes()...),
			},
		},
		"comment": schema.StringAttribute{
			Description: "Description of destination",
			Optional:    true,
			PlanModifiers: []planmodifier.String{
				stringplanmodifier.UseStateForUnknown(),
			},
		},
	}
}

func (d destinationModel) AttrTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"id":          types.StringType,
		"comment":     types.StringType,
		"destination": types.StringType,
		"type":        types.StringType,
	}
}

func (r *destinationListResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_destination_list"
}

func (r *destinationListResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"id": schema.Int64Attribute{
				Description: "Unique identifier for destination list",
				Computed:    true,
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				Description: "Name of destination list",
				Required:    true,
			},
			"destinations": schema.SetNestedAttribute{
				Description: "List of destinations to include in the list",
				Optional:    true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: destinationModel{}.DestinationAttributesNested(),
				},
			},
		},
	}
}

// Configure adds the provider configured client to the resource.
func (r *destinationListResource) Configure(ctx context.Context, req resource.ConfigureRequest, _ *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	r.client = *req.ProviderData.(*client.SSEClientFactory).GetDestinationListsClient(ctx)
}

func (r *destinationListResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var data destinationListResourceModel

	diags := req.Config.Get(ctx, &data)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if data.Destinations.IsNull() || data.Destinations.IsUnknown() {
		return
	}

	var destinations []destinationModel
	diags = data.Destinations.ElementsAs(ctx, &destinations, true)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	for i := range destinations {
		if destinations[i].Type.IsNull() || destinations[i].Type.IsUnknown() || destinations[i].Destination.IsNull() || destinations[i].Destination.IsUnknown() {
			continue
		}

		err := validateDestinationForType(destinations[i].Type.ValueString(), destinations[i].Destination.ValueString())
		if err == nil {
			continue
		}

		resp.Diagnostics.AddAttributeError(
			path.Root("destinations"),
			"Invalid destination for destination type",
			fmt.Sprintf("Element %d: destination %q is invalid for type %q: %s", i+1, destinations[i].Destination.ValueString(), destinations[i].Type.ValueString(), err.Error()),
		)
	}
}

func allowedDestinationTypeByName(name string) (destinationlists.ModelType, bool) {
	for _, allowed := range destinationlists.AllowedModelTypeEnumValues {
		if strings.EqualFold(string(allowed), name) {
			return allowed, true
		}
	}

	return "", false
}

func validateDestinationForType(destinationType string, destination string) error {
	resolvedType, ok := allowedDestinationTypeByName(destinationType)
	if !ok {
		return nil
	}

	ipv4Type, hasIPv4 := allowedDestinationTypeByName("ipv4")
	domainType, hasDomain := allowedDestinationTypeByName("domain")
	urlType, hasurl := allowedDestinationTypeByName("url")

	if hasIPv4 && resolvedType == ipv4Type {
		if !isValidIPv4(destination) {
			return fmt.Errorf("must be a valid IPv4 address")
		}
		return nil
	}

	if hasDomain && resolvedType == domainType {
		if !isValidDomain(destination) {
			return fmt.Errorf("must be a valid domain name")
		}
		return nil
	}

	if hasurl && resolvedType == urlType {
		parsedurl, err := url.ParseRequestURI(destination)
		if err != nil || parsedurl == nil || parsedurl.Scheme == "" || parsedurl.Host == "" {
			return fmt.Errorf("must be a valid url including scheme and host")
		}

		if strings.Trim(parsedurl.Path, "/") == "" {
			recommendedType := "domain"
			if hasDomain {
				recommendedType = string(domainType)
			}
			return fmt.Errorf("url must include a non-empty path; use type %q for host-only destinations", recommendedType)
		}
	}

	return nil
}

func isValidIPv4(value string) bool {
	parsed := net.ParseIP(value)
	return parsed != nil && parsed.To4() != nil
}

func isValidDomain(value string) bool {
	if value == "" || len(value) > 253 {
		return false
	}

	if strings.Contains(value, "://") || strings.ContainsAny(value, "/:?&#") {
		return false
	}

	trimmed := strings.TrimSuffix(value, ".")
	labels := strings.Split(trimmed, ".")

	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 {
			return false
		}

		if !domainLabelRegex.MatchString(label) {
			return false
		}

		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
	}

	return true
}

func minInt(a int, b int) int {
	if a < b {
		return a
	}

	return b
}

// Create creates a new destination list resource
func (r *destinationListResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan destinationListResourceModel

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Create API call logic
	var planDestinationList []destinationModel
	diags := plan.Destinations.ElementsAs(ctx, &planDestinationList, true)
	if diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}

	modeledDestinations := make([]destinationlists.DestinationListCreateDestinationsInner, len(planDestinationList))
	for i := range planDestinationList {
		modeledDestinations[i].SetComment(planDestinationList[i].Comment.ValueString())
		modeledDestinations[i].SetType(destinationlists.ModelType(planDestinationList[i].Type.ValueString()))
		modeledDestinations[i].SetDestination(planDestinationList[i].Destination.ValueString())
	}

	initialDestinationsCount := minInt(len(modeledDestinations), maxDestinationsPerRequest)
	initialDestinations := modeledDestinations[:initialDestinationsCount]

	var bundleTypeID destinationlists.BundleTypeId = defaultBundleTypeID
	createRequest := destinationlists.DestinationListCreate{
		Access:       "none",
		IsGlobal:     false,
		Name:         plan.Name.ValueString(),
		BundleTypeId: &bundleTypeID,
		Destinations: initialDestinations,
	}

	createResp, httpRes, err := r.client.DestinationListsAPI.CreateDestinationList(ctx).DestinationListCreate(createRequest).Execute()
	if err != nil {
		resp.Diagnostics.AddError(
			fmt.Sprintf("HTTP Response: %v", httpRes),
			fmt.Sprintf("Error creating destination list %s: %s", plan.Name.ValueString(), err.Error()))
		return
	}
	if httpRes.StatusCode != httpStatusOK {
		resp.Diagnostics.AddError(
			fmt.Sprintf("HTTP Response: %s", httpRes.Status),
			fmt.Sprintf("Error creating destination list %s", plan.Name.ValueString()))
		return
	}

	destinationString, _ := createResp.Data.MarshalJSON()
	tflog.Debug(ctx, "Created destination list", map[string]interface{}{
		"destination_list_name": plan.Name.ValueString(),
		"destination_list_id":   createResp.Data.Id,
		"response":              string(destinationString),
	})

	plan.Id = types.Int64Value(createResp.Data.Id)

	// Page through destinations 500 at a time.  Destinations API spec does not advertise maxItems
	if len(modeledDestinations) > maxDestinationsPerRequest {
		for start := maxDestinationsPerRequest; start < len(planDestinationList); start += maxDestinationsPerRequest {
			end := minInt(start+maxDestinationsPerRequest, len(planDestinationList))
			remainingDestinations := make([]destinationlists.DestinationCreateObject, 0, end-start)

			for i := start; i < end; i++ {
				newDestination := destinationlists.NewDestinationCreateObject(planDestinationList[i].Destination.ValueString())
				newDestination.SetComment(planDestinationList[i].Comment.ValueString())
				remainingDestinations = append(remainingDestinations, *newDestination)
			}

			_, httpRes, err = r.client.DestinationsAPI.CreateDestinations(ctx, plan.Id.ValueInt64()).DestinationCreateObject(remainingDestinations).Execute()
			if err != nil {
				resp.Diagnostics.AddError(
					fmt.Sprintf("HTTP Response: %v", httpRes),
					fmt.Sprintf("Error creating additional destinations for destination list %s: %s", plan.Name.ValueString(), err.Error()),
				)
				return
			}
		}
	}

	diags = plan.UpdateDestinations(ctx, &r.client)
	if diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}

	tflog.Debug(ctx, "Created destination list state", map[string]interface{}{
		"destination_list_id":   plan.Id.ValueInt64(),
		"destination_list_name": plan.Name.ValueString(),
	})

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Read reads the destination list resource state
func (r *destinationListResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data destinationListResourceModel

	// Read Terraform prior state data into the model
	diags := req.State.Get(ctx, &data)
	if diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}

	// Read API call logic
	destinationListResp, httpRes, err := r.client.DestinationListsAPI.GetDestinationList(ctx, data.Id.ValueInt64()).Execute()
	if err != nil {
		if httpRes == nil || httpRes.Body == nil {
			resp.Diagnostics.AddError(
				"Error reading response body",
				fmt.Sprintf("Error reading destination list %s response: %s", data.Name.ValueString(), err))
			return
		}

		// Handle "200 Not Found" from Destination Lists API
		bodyBytes, readErr := io.ReadAll(httpRes.Body)
		httpRes.Body.Close()

		if readErr != nil {
			resp.Diagnostics.AddError(
				"Error reading response body",
				fmt.Sprintf("Error reading destination list %s response: %s", data.Name.ValueString(), readErr.Error()))
			return
		}

		tflog.Debug(ctx, "Read destination list response", map[string]interface{}{
			"destination_list_id":   data.Id.ValueInt64(),
			"destination_list_name": data.Name.ValueString(),
			"response_body":         string(bodyBytes),
		})

		if strings.Contains(string(bodyBytes), destinationListNotFoundError) {
			resp.State.RemoveResource(ctx)
			tflog.Debug(ctx, "Destination list not found on read, removing from state", map[string]interface{}{
				"destination_list_id":   data.Id.ValueInt64(),
				"destination_list_name": data.Name.ValueString(),
			})
			return
		}

		tflog.Error(ctx, "Error other than 'not found' on read", map[string]interface{}{
			"destination_list_id":   data.Id.ValueInt64(),
			"destination_list_name": data.Name.ValueString(),
			"error":                 err.Error(),
		})
		resp.Diagnostics.AddError(
			fmt.Sprintf("HTTP Response: %s", httpRes.Status),
			fmt.Sprintf("Error reading destination list %s: %s", data.Name.ValueString(), err.Error()))
		return
	}

	destlistDebug, _ := json.Marshal(destinationListResp.Data)
	tflog.Debug(ctx, "Read destination list details", map[string]interface{}{
		"destination_list_id":   data.Id.ValueInt64(),
		"destination_list_name": destinationListResp.Data.Name,
		"response":              string(destlistDebug),
	})

	data.Name = types.StringValue(destinationListResp.Data.Name)

	diags = data.UpdateDestinations(ctx, &r.client)
	if diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}

	tflog.Debug(ctx, "Read destination list state", map[string]interface{}{
		"destination_list_id":   data.Id.ValueInt64(),
		"destination_list_name": data.Name.ValueString(),
		"destinations":          data.Destinations.String(),
	})

	// Save updated data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// Update updates the destination list resource
func (r *destinationListResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	// Read Terraform plan data into the model
	var plan, state destinationListResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Update API call logic
	if !plan.Name.Equal(state.Name) {
		payload := destinationlists.DestinationListPatch{Name: plan.Name.ValueString()}
		_, httpRes, err := r.client.DestinationListsAPI.UpdateDestinationLists(ctx, plan.Id.ValueInt64()).DestinationListPatch(payload).Execute()
		if err != nil {
			resp.Diagnostics.AddError(
				fmt.Sprintf("HTTP Response: %v", httpRes),
				fmt.Sprintf("Error updating name for destination list %s: %s", plan.Name.ValueString(), err),
			)
			return
		}
		state.Name = plan.Name
	}

	// Get current destinations
	readDestinations, err := state.GetDestinations(ctx, &r.client)
	if err != nil {
		resp.Diagnostics.AddError(
			fmt.Sprintf("Error retrieving destinations for %s", plan.Name.ValueString()),
			fmt.Sprintf("%s", err))
		return
	}

	var planDestinationList []destinationModel
	diags := plan.Destinations.ElementsAs(ctx, &planDestinationList, true)
	if diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}

	// Find missing destinations that need to be created
	var missingDestinations []destinationlists.DestinationCreateObject
	for j := range planDestinationList {
		tflog.Debug(ctx, "Checking if destination is missing", map[string]interface{}{
			"destination": planDestinationList[j].Destination.ValueString(),
		})

		reconciled := false
		for i := range readDestinations {
			if readDestinations[i].Destination == planDestinationList[j].Destination {
				tflog.Debug(ctx, "Destination found", map[string]interface{}{
					"destination": readDestinations[i].Destination.ValueString(),
				})
				reconciled = true
				break
			}
		}

		tflog.Debug(ctx, "Destination reconciliation result", map[string]interface{}{
			"destination": planDestinationList[j].Destination.ValueString(),
			"found":       reconciled,
		})

		if !reconciled {
			tflog.Debug(ctx, "Adding missing destination", map[string]interface{}{
				"destination": planDestinationList[j].Destination.ValueString(),
			})
			destinationCreateObject := destinationlists.NewDestinationCreateObject(planDestinationList[j].Destination.ValueString())
			destinationCreateObject.SetComment(planDestinationList[j].Comment.ValueString())

			// Note: DestinationCreateObject doesn't have SetType method - the API auto-detects type
			missingDestinations = append(missingDestinations, *destinationCreateObject)
		}
	}
	// Create missing destinations
	if len(missingDestinations) > 0 {
		_, httpRes, err := r.client.DestinationsAPI.CreateDestinations(ctx, plan.Id.ValueInt64()).DestinationCreateObject(missingDestinations).Execute()
		if err != nil {
			resp.Diagnostics.AddError(
				fmt.Sprintf("HTTP Response: %v", httpRes),
				fmt.Sprintf("Error adding missing destinations for destination list %s: %s", plan.Name.ValueString(), err),
			)
			return
		}
	}

	// Delete unmanaged destinations
	var extraDestinations []int64
	for i := range readDestinations {
		tflog.Debug(ctx, "Checking if destination is extraneous", map[string]interface{}{
			"destination": readDestinations[i].Destination.ValueString(),
		})

		reconciled := false
		for j := range planDestinationList {
			if readDestinations[i].Destination == planDestinationList[j].Destination {
				reconciled = true
				break
			}
		}

		tflog.Debug(ctx, "Destination removal check", map[string]interface{}{
			"destination": readDestinations[i].Destination.ValueString(),
			"should_keep": reconciled,
		})

		if !reconciled {
			tflog.Debug(ctx, "Scheduling destination for removal", map[string]interface{}{
				"destination": readDestinations[i].Destination.ValueString(),
			})
			destinationID, convErr := strconv.ParseInt(readDestinations[i].Id.ValueString(), 10, 64)
			if convErr != nil {
				resp.Diagnostics.AddError(
					"Error converting destination ID",
					fmt.Sprintf("Error converting destination ID %s to int64: %s", readDestinations[i].Id.ValueString(), convErr))
				return
			}
			extraDestinations = append(extraDestinations, destinationID)
		}
	}

	if len(extraDestinations) > 0 {
		_, httpRes, err := r.client.DestinationsAPI.DeleteDestinations(ctx, plan.Id.ValueInt64()).RequestBody(extraDestinations).Execute()
		if err != nil {
			resp.Diagnostics.AddError(
				fmt.Sprintf("HTTP Response: %v", httpRes),
				fmt.Sprintf("Error deleting extraneous destinations for destination list %s: %s", plan.Name.ValueString(), err),
			)
			return
		}
	}

	// Update local view of destinations
	diags = plan.UpdateDestinations(ctx, &r.client)
	if diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}

	tflog.Debug(ctx, "Updated destination list state", map[string]interface{}{
		"destination_list_id":   plan.Id.ValueInt64(),
		"destination_list_name": plan.Name.ValueString(),
		"destinations":          plan.Destinations.String(),
	})

	// Save updated data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Delete deletes the destination list resource
func (r *destinationListResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data destinationListResourceModel

	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Delete API call logic
	deleteResp, httpRes, err := r.client.DestinationListsAPI.DeleteDestinationList(ctx, data.Id.ValueInt64()).Execute()
	if err != nil {
		if httpRes != nil && httpRes.StatusCode == httpStatusNotFound {
			tflog.Debug(ctx, "Destination list not found during delete", map[string]interface{}{
				"destination_list_id":   data.Id.ValueInt64(),
				"destination_list_name": data.Name.ValueString(),
			})
			return
		}
		resp.Diagnostics.AddError(
			fmt.Sprintf("HTTP Response: %v", httpRes),
			fmt.Sprintf("Error deleting destination list %s: %s", data.Name.ValueString(), err.Error()))
		return
	}

	destsDebug, _ := json.Marshal(deleteResp.Data)
	tflog.Debug(ctx, "Delete destination list response", map[string]interface{}{
		"destination_list_id":   data.Id.ValueInt64(),
		"destination_list_name": data.Name.ValueString(),
		"response":              string(destsDebug),
	})
}

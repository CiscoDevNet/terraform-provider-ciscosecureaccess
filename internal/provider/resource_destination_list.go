// Copyright 2025 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/CiscoDevNet/go-ciscosecureaccess/client"
	"github.com/CiscoDevNet/go-ciscosecureaccess/destinationlists"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
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

// Constants for destination list resource
const (
	// Bundle type ID for destination lists
	defaultBundleTypeID = 2
	// HTTP status codes
	httpStatusOK       = 200
	httpStatusNotFound = 404
	// Error messages
	destinationListNotFoundError = "\"statusCode\":404,\"error\":\"Not Found\""
)

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
	destinationsResp, httpRes, err := client.DestinationsAPI.GetDestinations(ctx, r.Id.ValueInt64()).Execute()
	if err != nil {
		var httpRespDetails string
		if httpRes != nil {
			httpRespDetails = fmt.Sprintf("HTTP response status: %s", httpRes.Status)
		} else {
			httpRespDetails = "HTTP response: <nil>"
		}
		return nil, fmt.Errorf("error code %s reading destinations for destination list %s: %w\n%v", httpRes.Status, r.Name.ValueString(), err, httpRespDetails)
	}

	destsDebug, err := json.Marshal(destinationsResp.Data)
	if err != nil {
		return nil, fmt.Errorf("error code %s reading destinations for destination list %s: %w", httpRes.Status, r.Name.ValueString(), err)
	}
	tflog.Debug(ctx, "Retrieved destinations for destination list", map[string]interface{}{
		"destination_list_id": r.Id.ValueInt64(),
		"destinations":        string(destsDebug),
	})

	modeledDestinations := make([]destinationModel, len(destinationsResp.Data))
	for i := range destinationsResp.Data {
		modeledDestinations[i] = destinationModel{
			Id:          types.StringValue(destinationsResp.Data[i].Id),
			Destination: types.StringValue(destinationsResp.Data[i].Destination),
			Type:        types.StringValue(string(destinationsResp.Data[i].Type)),
		}
		if destinationsResp.Data[i].Comment != nil {
			modeledDestinations[i].Comment = types.StringValue(*destinationsResp.Data[i].Comment)
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
			Description: "A domain, URL, or IP.",
			Required:    true,
		},
		"type": schema.StringAttribute{
			Description: "The type of the destination ('DOMAIN', 'URL', 'IPV4')",
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

	var bundleTypeID destinationlists.BundleTypeId = defaultBundleTypeID
	createRequest := destinationlists.DestinationListCreate{
		Access:       "none",
		IsGlobal:     false,
		Name:         plan.Name.ValueString(),
		BundleTypeId: &bundleTypeID,
		Destinations: modeledDestinations,
	}

	createResp, httpRes, err := r.client.DestinationListsAPI.CreateDestinationList(ctx).DestinationListCreate(createRequest).Execute()
	if httpRes.StatusCode != httpStatusOK {
		resp.Diagnostics.AddError(
			fmt.Sprintf("HTTP Response: %s", httpRes.Status),
			fmt.Sprintf("Error creating destination list %s: %s", plan.Name.ValueString(), err.Error()))
		return
	}

	destinationString, _ := createResp.Data.MarshalJSON()
	tflog.Debug(ctx, "Created destination list", map[string]interface{}{
		"destination_list_name": plan.Name.ValueString(),
		"destination_list_id":   createResp.Data.Id,
		"response":              string(destinationString),
	})

	plan.Id = types.Int64Value(createResp.Data.Id)

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
		if httpRes.Body == nil {
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
	if httpRes.StatusCode == httpStatusNotFound {
		tflog.Debug(ctx, "Destination list not found during delete", map[string]interface{}{
			"destination_list_id":   data.Id.ValueInt64(),
			"destination_list_name": data.Name.ValueString(),
		})
		return
	} else if err != nil {
		resp.Diagnostics.AddError(
			fmt.Sprintf("HTTP Response: %s", httpRes.Status),
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

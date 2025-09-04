// Copyright 2025 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/CiscoDevNet/go-ciscosecureaccess/client"
	"github.com/CiscoDevNet/go-ciscosecureaccess/resconn"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// Schema defines the schema for the data source.
func (d *resourceConnectorGroupsDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Datasource for a list of Resource Connector Groups",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Internal ID of resource connector group list",
			},
			"resource_connector_groups": schema.ListNestedAttribute{
				Computed: true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.Int64Attribute{
							Description: "Unique ID of resource connector group",
							Computed:    true,
						},
						"connectors_count": schema.Int64Attribute{
							Description: "Number of resource connectors in group",
							Computed:    true,
						},
						"environment": schema.StringAttribute{
							Description: "Environment in which resource connector group is provisioned",
							Computed:    true,
						},
						"key_expires_at": schema.StringAttribute{
							Description: "Time at which resource connector group provisioning key next expires",
							Computed:    true,
						},
						"location": schema.StringAttribute{
							Description: "Location where resource connector group is provisioned",
							Computed:    true,
						},
						"name": schema.StringAttribute{
							Description: "Name of resource connector group",
							Computed:    true,
						},
						"provisioning_key": schema.StringAttribute{
							Description: "Provisioning key for adding resource connectors to group",
							Computed:    true,
							Sensitive:   true,
						},
						"status": schema.StringAttribute{
							Description: "Status of resource connector group",
							Computed:    true,
						},
					},
				},
			},
			"filter": schema.MapAttribute{
				Description: "Filter criteria for retrieving resource connector groups (e.g., {\"name\": \"example\"})",
				Required:    true,
				ElementType: types.StringType,
			},
		},
	}
}

type resourceConnectorGroupModel struct {
	ID              types.Int64  `tfsdk:"id"`
	ConnectorsCount types.Int64  `tfsdk:"connectors_count"`
	Environment     types.String `tfsdk:"environment"`
	KeyExpiresAt    types.String `tfsdk:"key_expires_at"`
	Location        types.String `tfsdk:"location"`
	Name            types.String `tfsdk:"name"`
	ProvisioningKey types.String `tfsdk:"provisioning_key"`
	Status          types.String `tfsdk:"status"`
}

func (d resourceConnectorGroupModel) AttrTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"id":               types.Int64Type,
		"connectors_count": types.Int64Type,
		"environment":      types.StringType,
		"key_expires_at":   types.StringType,
		"location":         types.StringType,
		"name":             types.StringType,
		"provisioning_key": types.StringType,
		"status":           types.StringType,
	}
}

type resourceConnectorGroupsDataSourceModel struct {
	ID                      types.String `tfsdk:"id"`
	ResourceConnectorGroups types.List   `tfsdk:"resource_connector_groups"`
	Filter                  types.Map    `tfsdk:"filter"`
}

var _ datasource.DataSource = &resourceConnectorGroupsDataSource{}

// NewResourceConnectorGroupsDataSource is a helper function to simplify the provider implementation.
func NewResourceConnectorGroupsDataSource() datasource.DataSource {
	return &resourceConnectorGroupsDataSource{}
}

type resourceConnectorGroupsDataSource struct {
	client resconn.APIClient
}

func (d *resourceConnectorGroupsDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_resource_connector"
}

func (d *resourceConnectorGroupsDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, _ *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	d.client = *req.ProviderData.(*client.SSEClientFactory).GetResConnClient(ctx)
}

// Read retrieves the resource connector groups from the API and sets the state.
func (d *resourceConnectorGroupsDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data resourceConnectorGroupsDataSourceModel

	// Read Terraform configuration data into the model
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Info(ctx, "Reading resource connector groups")

	// Process filter
	filters, err := d.buildFiltersFromMap(ctx, data.Filter)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error constructing Resource Connector Group query filter",
			fmt.Sprintf("Could not build filter: %s", err.Error()),
		)
		return
	}

	// Make API call
	groups, _, err := d.client.ConnectorGroupsAPI.ListConnectorGroups(ctx).
		IncludeProvisioningKey(true).
		Filters(filters).
		Execute()
	if err != nil {
		resp.Diagnostics.AddError(
			"Error listing Resource Connector Groups",
			fmt.Sprintf("Could not retrieve resource connector groups: %s", err.Error()),
		)
		return
	}

	tflog.Debug(ctx, "Retrieved resource connector groups", map[string]interface{}{
		"count": len(groups.Data),
	})

	// Ensure groups.Data is not nil before iterating
	if groups.Data == nil {
		resp.Diagnostics.AddError(
			"API Response Error",
			"Received nil data from the API while listing resource connector groups.",
		)
		return
	}

	// Convert API response to terraform models
	connectorGroups := make([]resourceConnectorGroupModel, 0, len(groups.Data))
	for _, group := range groups.Data {
		groupID := group.GetId()
		tflog.Debug(ctx, "Processing connector group", map[string]interface{}{
			"id":   groupID,
			"name": group.GetName(),
		})

		model := resourceConnectorGroupModel{
			ID:              types.Int64Value(groupID),
			Name:            types.StringValue(group.GetName()),
			Location:        types.StringValue(group.GetLocation()),
			Environment:     types.StringValue(string(group.GetEnvironment())),
			ConnectorsCount: types.Int64Value(group.GetConnectorsCount()),
			Status:          types.StringValue(group.GetStatus()),
			ProvisioningKey: types.StringValue(group.GetProvisioningKey()),
			KeyExpiresAt:    types.StringValue(group.GetProvisioningKeyExpiresAt().Format(time.RFC3339)),
		}

		connectorGroups = append(connectorGroups, model)
	}

	// Set computed ID for the data source
	data.ID = types.StringValue("resource_connector_groups")

	// Convert to Terraform list
	connectorGroupsList, diags := types.ListValueFrom(ctx, types.ObjectType{AttrTypes: resourceConnectorGroupModel{}.AttrTypes()}, connectorGroups)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	data.ResourceConnectorGroups = connectorGroupsList

	tflog.Info(ctx, "Successfully retrieved resource connector groups", map[string]interface{}{
		"count": len(connectorGroups),
	})

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// buildFiltersFromMap converts the filter map to JSON string format expected by the API
func (d *resourceConnectorGroupsDataSource) buildFiltersFromMap(ctx context.Context, filterMap types.Map) (string, error) {
	elements := make(map[string]types.String, len(filterMap.Elements()))
	filterMap.ElementsAs(ctx, &elements, false)

	filterBytes, err := json.Marshal(map[string]string{elements["name"].ValueString(): elements["query"].ValueString()})
	if err != nil {
		return "", fmt.Errorf("failed to marshal filter map for Resource Connector Groups: %w", err)
	}

	return string(filterBytes), nil
}

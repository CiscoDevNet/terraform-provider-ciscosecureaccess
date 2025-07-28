// Copyright 2025 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"
	"time"

	"github.com/avast/retry-go/v4"
	"github.com/CiscoDevNet/go-ciscosecureaccess/client"
	"github.com/CiscoDevNet/go-ciscosecureaccess/reports"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// Constants for identity data source
const (
	identityBatchSize = 100
	identityTypeUser  = "directory_user"
	identityTypeGroup = "directory_group"
)

// Ensure the implementation satisfies the expected interfaces.
var _ datasource.DataSource = &identityDataSource{}

// NewIdentityDataSource is a helper function to simplify the provider implementation.
func NewIdentityDataSource() datasource.DataSource {
	return &identityDataSource{}
}

// identityDataSource is the data source implementation.
type identityDataSource struct {
	client reports.APIClient
}

// IdentityModel maps the identity data from the API.
type IdentityModel struct {
	Id    types.Int64  `tfsdk:"id"`
	Label types.String `tfsdk:"label"`
	Type  types.String `tfsdk:"type"`
}

func (m IdentityModel) AttrTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"id":    types.Int64Type,
		"label": types.StringType,
		"type":  types.StringType,
	}
}

// identityDataSourceModel maps the data source schema data.
type identityDataSourceModel struct {
	Identities types.List   `tfsdk:"identities"`
	Filter     types.String `tfsdk:"filter"`
}

// Metadata returns the data source type name.
func (d *identityDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_identity"
}

// Configure adds the provider configured client to the data source.
func (d *identityDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, _ *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	d.client = *req.ProviderData.(*client.SSEClientFactory).GetReportsClient(ctx)
}

// Schema defines the schema for the data source.
func (d *identityDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Data source for retrieving Cisco Secure Access identities",
		Attributes: map[string]schema.Attribute{
			"filter": schema.StringAttribute{
				Description: "Filter string used to search for identities",
				Required:    true,
			},
			"identities": schema.ListNestedAttribute{
				Description: "List of Cisco Secure Access identities corresponding to filter",
				Computed:    true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"label": schema.StringAttribute{
							Description: "Name of identity",
							Computed:    true,
						},
						"type": schema.StringAttribute{
							Description: "Type of identity",
							Computed:    true,
						},
						"id": schema.Int64Attribute{
							Description: "Unique ID of identity",
							Computed:    true,
						},
					},
				},
			},
		},
	}
}

// Read retrieves the identities from the API and sets the state.
func (d *identityDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data identityDataSourceModel

	// Read Terraform configuration data into the model
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Info(ctx, "Reading identities", map[string]interface{}{
		"filter": data.Filter.ValueString(),
	})

	// Get identities using the shared function
	identities, getDiag := getIdentitiesForFilter(ctx, &d.client, data.Filter.ValueString(), identityTypeUser)
	if getDiag.HasError() {
		resp.Diagnostics.Append(getDiag...)
		return
	}

	tflog.Debug(ctx, "Retrieved identities", map[string]interface{}{
		"count": len(identities),
	})

	// Convert to Terraform list
	identitiesList, diags := types.ListValueFrom(ctx, types.ObjectType{AttrTypes: IdentityModel{}.AttrTypes()}, identities)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	data.Identities = identitiesList

	tflog.Info(ctx, "Successfully retrieved identities", map[string]interface{}{
		"count": len(identities),
	})

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// getIdentitiesForFilter retrieves identities from the API with pagination and retry logic.
func getIdentitiesForFilter(ctx context.Context, client *reports.APIClient, filter string, identityType string) ([]IdentityModel, diag.Diagnostics) {
	offset := int64(0)
	var diagnostics diag.Diagnostics
	var identities []IdentityModel

	tflog.Debug(ctx, "Starting identity retrieval", map[string]interface{}{
		"filter":       filter,
		"identityType": identityType,
	})

	for {
		done := false
		err := retry.Do(
			func() error {
				identitiesResp, httpRes, err := client.UtilityAPI.GetIdentities(ctx).
					Limit(identityBatchSize).
					Offset(offset).
					Search(fmt.Sprintf("%%%s%%", filter)).
					Identitytypes(identityType).
					Execute()

				if err != nil {
					if httpRes != nil && httpRes.StatusCode == 429 {
						tflog.Warn(ctx, "Rate limited, retrying", map[string]interface{}{
							"offset": offset,
						})
						return err
					} else {
						diagnostics.AddError(
							"Error listing identity/group source",
							fmt.Sprintf("Could not retrieve identities: %s", err.Error()),
						)
						done = true
						return retry.Unrecoverable(err)
					}
				}

				// Process the batch of identities
				for _, identity := range identitiesResp.Data {
					tflog.Trace(ctx, "Processing identity", map[string]interface{}{
						"id":    identity.Id,
						"label": identity.Label,
						"type":  *identity.Type.Type,
					})

					identities = append(identities, IdentityModel{
						Id:    types.Int64Value(identity.Id),
						Label: types.StringValue(identity.Label),
						Type:  types.StringValue(*identity.Type.Type),
					})
				}

				// Check if we have more data to fetch
				if len(identitiesResp.Data) < identityBatchSize {
					done = true
				}
				offset += identityBatchSize
				return nil
			},
			retry.Delay(time.Second*10), // Reasonable retry delay
			retry.Attempts(3),           // Limit retry attempts
		)

		if err != nil && !diagnostics.HasError() {
			diagnostics.AddError(
				"Failed to retrieve identities after retries",
				fmt.Sprintf("API request failed: %s", err.Error()),
			)
		}

		if done {
			break
		}
	}

	tflog.Debug(ctx, "Completed identity retrieval", map[string]interface{}{
		"totalCount": len(identities),
		"offset":     offset,
	})

	return identities, diagnostics
}

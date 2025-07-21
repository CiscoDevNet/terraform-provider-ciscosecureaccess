package provider

import (
	"context"

	"github.com/CiscoDevNet/go-ciscosecureaccess/client"
	"github.com/CiscoDevNet/go-ciscosecureaccess/reports"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// Ensure the implementation satisfies the expected interfaces.
var _ datasource.DataSource = &groupDataSource{}

// NewGroupDataSource is a helper function to simplify the provider implementation.
func NewGroupDataSource() datasource.DataSource {
	return &groupDataSource{}
}

// groupDataSource is the data source implementation.
type groupDataSource struct {
	client reports.APIClient
}

// groupModel maps the group data from the API.
type groupModel struct {
	ID    types.Int64  `tfsdk:"id"`
	Label types.String `tfsdk:"label"`
	Type  types.String `tfsdk:"type"`
}

func (g groupModel) AttrTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"id":    types.Int64Type,
		"label": types.StringType,
		"type":  types.StringType,
	}
}

// groupDataSourceModel maps the data source schema data.
type groupDataSourceModel struct {
	Groups types.List   `tfsdk:"groups"`
	Filter types.String `tfsdk:"filter"`
}

// Metadata returns the data source type name.
func (d *groupDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_group"
}

// Configure adds the provider configured client to the data source.
func (d *groupDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, _ *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	d.client = *req.ProviderData.(*client.SSEClientFactory).GetReportsClient(ctx)
}

// Schema defines the schema for the data source.
func (d *groupDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Data source for retrieving Cisco Secure Access groups",
		Attributes: map[string]schema.Attribute{
			"filter": schema.StringAttribute{
				Description: "Filter string used to search for groups",
				Required:    true,
			},
			"groups": schema.ListNestedAttribute{
				Description: "List of Cisco Secure Access groups corresponding to filter",
				Computed:    true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"label": schema.StringAttribute{
							Description: "Name of group",
							Computed:    true,
						},
						"type": schema.StringAttribute{
							Description: "Type of group",
							Computed:    true,
						},
						"id": schema.Int64Attribute{
							Description: "Unique ID of group",
							Computed:    true,
						},
					},
				},
			},
		},
	}
}

// Read retrieves the groups from the API and sets the state.
func (d *groupDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data groupDataSourceModel

	// Read Terraform configuration data into the model
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Info(ctx, "Reading groups", map[string]interface{}{
		"filter": data.Filter.ValueString(),
	})

	// Get groups using the shared function
	groups, getDiag := getIdentitiesForFilter(ctx, &d.client, data.Filter.ValueString(), identityTypeGroup)
	if getDiag.HasError() {
		resp.Diagnostics.Append(getDiag...)
		return
	}

	tflog.Debug(ctx, "Retrieved groups", map[string]interface{}{
		"count": len(groups),
	})

	// Convert to group models
	groupModels := make([]groupModel, len(groups))
	for i, identity := range groups {
		groupModels[i] = groupModel{
			ID:    identity.Id,
			Label: identity.Label,
			Type:  identity.Type,
		}
	}

	// Convert to Terraform list
	groupsList, diags := types.ListValueFrom(ctx, types.ObjectType{AttrTypes: groupModel{}.AttrTypes()}, groupModels)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	data.Groups = groupsList

	tflog.Info(ctx, "Successfully retrieved groups", map[string]interface{}{
		"count": len(groupModels),
	})

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

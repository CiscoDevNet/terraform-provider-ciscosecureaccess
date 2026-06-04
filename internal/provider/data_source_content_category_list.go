// Copyright 2025 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"
	"strings"

	"github.com/CiscoDevNet/go-ciscosecureaccess/client"
	"github.com/CiscoDevNet/go-ciscosecureaccess/contentcategories"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

const (
	contentCategoryBatchSize = 100
)

var _ datasource.DataSource = &contentCategoryListDataSource{}

// NewContentCategoryListDataSource creates the data source implementation.
func NewContentCategoryListDataSource() datasource.DataSource {
	return &contentCategoryListDataSource{}
}

type contentCategoryListDataSource struct {
	client contentcategories.APIClient
}

// ContentCategoryListModel maps a single content category list entry.
type ContentCategoryListModel struct {
	Id        types.Int64  `tfsdk:"id"`
	Name      types.String `tfsdk:"name"`
	Type      types.String `tfsdk:"type"`
	IsDefault types.Bool   `tfsdk:"is_default"`
}

func (m ContentCategoryListModel) AttrTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"id":         types.Int64Type,
		"name":       types.StringType,
		"type":       types.StringType,
		"is_default": types.BoolType,
	}
}

// contentCategoryListDataSourceModel maps the data source schema data.
type contentCategoryListDataSourceModel struct {
	ContentCategoryLists types.List   `tfsdk:"content_category_lists"`
	Filter               types.String `tfsdk:"filter"`
}

func (d *contentCategoryListDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_content_category_list"
}

func (d *contentCategoryListDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	factory, ok := req.ProviderData.(*client.SSEClientFactory)
	if !ok {
		resp.Diagnostics.AddError("Unexpected Provider Data Type",
			fmt.Sprintf("expected *client.SSEClientFactory, got %T", req.ProviderData))
		return
	}
	d.client = *factory.GetContentCategoriesClient(ctx)
}

func (d *contentCategoryListDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Data source for retrieving Cisco Secure Access content category lists",
		Attributes: map[string]schema.Attribute{
			"filter": schema.StringAttribute{
				Description: "Optional case-insensitive substring used to filter content category lists by name. If omitted, all content category lists are returned.",
				Optional:    true,
			},
			"content_category_lists": schema.ListNestedAttribute{
				Description: "List of Cisco Secure Access content category lists matching the filter",
				Computed:    true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.Int64Attribute{
							Description: "Unique ID of content category list",
							Computed:    true,
						},
						"name": schema.StringAttribute{
							Description: "Name of content category list",
							Computed:    true,
						},
						"type": schema.StringAttribute{
							Description: "Type of content category setting",
							Computed:    true,
						},
						"is_default": schema.BoolAttribute{
							Description: "Whether this is the organization default content category setting",
							Computed:    true,
						},
					},
				},
			},
		},
	}
}

func (d *contentCategoryListDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data contentCategoryListDataSourceModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	filter := data.Filter.ValueString()
	tflog.Info(ctx, "Reading content category lists", map[string]interface{}{
		"filter": filter,
	})

	lists, getDiag := getContentCategoryLists(ctx, &d.client, filter)
	resp.Diagnostics.Append(getDiag...)
	if resp.Diagnostics.HasError() {
		return
	}

	listValue, diags := types.ListValueFrom(ctx, types.ObjectType{AttrTypes: ContentCategoryListModel{}.AttrTypes()}, lists)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	data.ContentCategoryLists = listValue

	tflog.Info(ctx, "Successfully retrieved content category lists", map[string]interface{}{
		"count": len(lists),
	})

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func getContentCategoryLists(ctx context.Context, client *contentcategories.APIClient, filter string) ([]ContentCategoryListModel, diag.Diagnostics) {
	var diagnostics diag.Diagnostics
	var results []ContentCategoryListModel
	page := int64(1)
	lowerFilter := strings.ToLower(filter)

	for {
		categories, httpRes, err := client.ContentCategoriesAPI.GetCategorySettings(ctx).
			Page(page).
			Limit(contentCategoryBatchSize).
			Execute()
		if err != nil {
			httpRespDetails := "HTTP response: <nil>"
			if httpRes != nil {
				httpRespDetails = fmt.Sprintf("HTTP response status: %d", httpRes.StatusCode)
			}
			diagnostics.AddError(
				"Error listing content category lists",
				fmt.Sprintf("Could not retrieve content category lists: %s\n%s", err.Error(), httpRespDetails),
			)
			return results, diagnostics
		}

		for _, c := range categories {
			name := ""
			if c.Name != nil {
				name = *c.Name
			}
			if lowerFilter != "" && !strings.Contains(strings.ToLower(name), lowerFilter) {
				continue
			}
			id := int64(0)
			if c.Id != nil {
				id = *c.Id
			}
			typeStr := ""
			if c.Type != nil {
				typeStr = *c.Type
			}
			isDefault := false
			if c.IsDefault != nil {
				isDefault = *c.IsDefault
			}

			tflog.Trace(ctx, "Processing content category list", map[string]interface{}{
				"id":   id,
				"name": name,
			})

			results = append(results, ContentCategoryListModel{
				Id:        types.Int64Value(id),
				Name:      types.StringValue(name),
				Type:      types.StringValue(typeStr),
				IsDefault: types.BoolValue(isDefault),
			})
		}

		if int64(len(categories)) < contentCategoryBatchSize {
			break
		}
		page++
	}

	return results, diagnostics
}

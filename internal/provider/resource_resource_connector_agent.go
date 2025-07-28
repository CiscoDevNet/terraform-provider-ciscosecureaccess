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
	"time"

	"github.com/CiscoDevNet/go-ciscosecureaccess/client"
	"github.com/CiscoDevNet/go-ciscosecureaccess/resconn"
	"github.com/avast/retry-go/v4"
	"github.com/hashicorp/terraform-plugin-framework-validators/resourcevalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/boolplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ resource.Resource              = (*resourceConnectorAgentResource)(nil)
	_ resource.ResourceWithConfigure = &resourceConnectorAgentResource{}
)

// Constants for resource connector agent management
const (
	// HTTP status codes
	connectorHTTPOK          = 200
	connectorHTTPBadRequest  = 400
	connectorHTTPNotFound    = 404
	connectorHTTPTooManyReqs = 429

	// Retry configuration
	connectorRetryMaxAttempts = 6
	connectorRetryBaseDelay   = time.Second * 10

	// JSON patch operations
	connectorPatchOpReplace     = "replace"
	connectorPatchPathConfirmed = "/confirmed"
	connectorPatchPathEnabled   = "/enabled"
)

// NewResourceConnectorAgentResource is a helper function to simplify the provider implementation.
func NewResourceConnectorAgentResource() resource.Resource {
	return &resourceConnectorAgentResource{}
}

type resourceConnectorAgentResource struct {
	client resconn.APIClient
}

type resourceConnectorAgentResourceModel struct {
	ID         types.Int64  `tfsdk:"id"`
	InstanceID types.String `tfsdk:"instance_id"`
	Hostname   types.String `tfsdk:"hostname"`
	Status     types.String `tfsdk:"status"`
	Confirmed  types.Bool   `tfsdk:"confirmed"`
	Enabled    types.Bool   `tfsdk:"enabled"`
}

func (r *resourceConnectorAgentResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_resource_connector_agent"
}

// Configure adds the provider configured client to the resource.
func (r *resourceConnectorAgentResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	r.client = *req.ProviderData.(*client.SSEClientFactory).GetResConnClient(ctx)
	tflog.Debug(ctx, "Configured resource connector agent client")
}

func (r *resourceConnectorAgentResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Resource Connector Agent deployment, currently managing AWS resource connectors",
		Attributes: map[string]schema.Attribute{
			"id": schema.Int64Attribute{
				Description: "Unique ID of resource connector agent",
				Computed:    true,
			},
			"instance_id": schema.StringAttribute{
				Description: "Instance ID of resource connector agent",
				Optional:    true,
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
					stringplanmodifier.RequiresReplace(),
				},
			},
			"hostname": schema.StringAttribute{
				Description: "Hostname of resource connector agent",
				Optional:    true,
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
					stringplanmodifier.RequiresReplace(),
				},
			},
			"status": schema.StringAttribute{
				Description: "Status of resource connector agent",
				Computed:    true,
			},
			"confirmed": schema.BoolAttribute{
				Description: "Whether or not to confirm resource connector",
				Optional:    true,
				PlanModifiers: []planmodifier.Bool{
					boolplanmodifier.UseStateForUnknown(),
				},
			},
			"enabled": schema.BoolAttribute{
				Description: "Whether or not to enable resource connector",
				Optional:    true,
				PlanModifiers: []planmodifier.Bool{
					boolplanmodifier.UseStateForUnknown(),
				},
			},
		},
	}
}

func (r resourceConnectorAgentResource) ConfigValidators(ctx context.Context) []resource.ConfigValidator {
	return []resource.ConfigValidator{
		resourcevalidator.AtLeastOneOf(
			path.MatchRoot("instance_id"),
			path.MatchRoot("hostname"),
		),
	}
}

func (r *resourceConnectorAgentResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data resourceConnectorAgentResourceModel

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Info(ctx, "Creating resource connector agent")

	// Build filter for finding the agent
	filters, err := r.buildAgentFilter(ctx, &data)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error building agent filter",
			fmt.Sprintf("Failed to build filter for resource connector agent: %v", err),
		)
		return
	}

	// Find and configure the agent
	if err := r.findAndConfigureAgent(ctx, filters, &data, &resp.Diagnostics); err != nil {
		resp.Diagnostics.AddError(
			"Could not retrieve resource connector agent config",
			fmt.Sprintf("Failed to locate resource connector agent: %v", err),
		)
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// buildAgentFilter creates a JSON filter for finding the connector agent
func (r *resourceConnectorAgentResource) buildAgentFilter(ctx context.Context, data *resourceConnectorAgentResourceModel) (string, error) {
	var filterBytes []byte
	var err error

	if !data.InstanceID.IsNull() {
		filterBytes, err = json.Marshal(map[string]string{"instanceId": data.InstanceID.ValueString()})
		tflog.Debug(ctx, "Building instance ID filter", map[string]interface{}{
			"instance_id": data.InstanceID.ValueString(),
		})
	} else if !data.Hostname.IsNull() {
		filterBytes, err = json.Marshal(map[string]string{"hostname": data.Hostname.ValueString()})
		tflog.Debug(ctx, "Building hostname filter", map[string]interface{}{
			"hostname": data.Hostname.ValueString(),
		})
	} else {
		return "", fmt.Errorf("either instance_id or hostname must be specified")
	}

	if err != nil {
		return "", fmt.Errorf("failed to marshal filter: %w", err)
	}

	return string(filterBytes), nil
}

// findAndConfigureAgent finds the connector agent and configures it
func (r *resourceConnectorAgentResource) findAndConfigureAgent(ctx context.Context, filters string, data *resourceConnectorAgentResourceModel, diagnostics *diag.Diagnostics) error {
	return retry.Do(
		func() error {
			agents, httpRes, err := r.client.ConnectorsAPI.ListConnectors(ctx).Filters(filters).Execute()
			defer func() {
				if httpRes != nil && httpRes.Body != nil {
					httpRes.Body.Close()
				}
			}()

			if err != nil {
				return r.handleListConnectorsError(ctx, httpRes, err)
			}

			return r.processConnectorResponse(ctx, agents, data, filters)
		},
		retry.Attempts(connectorRetryMaxAttempts),
		retry.Delay(connectorRetryBaseDelay),
		retry.Context(ctx),
	)
}

// handleListConnectorsError processes errors from the ListConnectors API call
func (r *resourceConnectorAgentResource) handleListConnectorsError(ctx context.Context, httpRes *http.Response, err error) error {
	var bodyBytes []byte
	if httpRes != nil && httpRes.Body != nil {
		bodyBytes, _ = io.ReadAll(httpRes.Body)
	}

	statusCode := 0
	if httpRes != nil {
		statusCode = httpRes.StatusCode
	}

	tflog.Error(ctx, "Error creating resource connector agent", map[string]interface{}{
		"status_code":   statusCode,
		"response_body": string(bodyBytes),
		"error":         err.Error(),
	})

	if statusCode == connectorHTTPBadRequest || statusCode == connectorHTTPTooManyReqs {
		return fmt.Errorf("retryable error (status %d): %v - %s", statusCode, err, string(bodyBytes))
	}

	return retry.Unrecoverable(fmt.Errorf("non-retryable error (status %d): %v - %s", statusCode, err, string(bodyBytes)))
}

// processConnectorResponse processes the successful response from ListConnectors
func (r *resourceConnectorAgentResource) processConnectorResponse(ctx context.Context, agents interface{}, data *resourceConnectorAgentResourceModel, filters string) error {
	// Log the actual type for debugging
	tflog.Debug(ctx, "ListConnectors response type", map[string]interface{}{
		"type": fmt.Sprintf("%T", agents),
	})

	// Try to use reflection to understand the structure
	if agents != nil {
		respBytes, _ := json.Marshal(agents)
		tflog.Debug(ctx, "ListConnectors response data", map[string]interface{}{
			"data": string(respBytes),
		})
	}

	// Try direct type assertion for the specific ConnectorListRes type
	if connectorListRes, ok := agents.(*resconn.ConnectorListRes); ok {
		totalAgents := int(connectorListRes.GetTotal())

		tflog.Debug(ctx, "Received connector agents response", map[string]interface{}{
			"total_agents": totalAgents,
			"filters":      filters,
		})

		if totalAgents == 0 {
			return fmt.Errorf("no connector agent matching filter '%s' found", filters)
		}

		if totalAgents > 1 {
			return retry.Unrecoverable(fmt.Errorf("filter %s matches multiple agents (%d)", filters, totalAgents))
		}

		// Process the single agent found
		for _, agent := range connectorListRes.GetData() {
			respString, _ := json.Marshal(agent)
			tflog.Debug(ctx, "Found resource connector agent", map[string]interface{}{
				"agent_data": string(respString),
			})

			state := *data
			state.LoadFromAPI(ctx, agent)
			r.Synchronize(ctx, &state, data)
			*data = state

			tflog.Info(ctx, "Successfully configured resource connector agent", map[string]interface{}{
				"agent_id": state.ID.ValueInt64(),
			})
			return nil
		}

		return nil
	}

	// Try type assertion for the expected response structure with total and data fields
	agentsList, ok := agents.(interface {
		GetTotal() int64
		GetData() []resconn.ConnectorResponse
	})
	if !ok {
		// If the direct interface assertion fails, try to access by reflection-like approach
		// Check if it's a pointer and get the value type
		if ptrType, isPtrOk := agents.(interface{ GetTotal() int64 }); isPtrOk {
			tflog.Debug(ctx, "Found GetTotal method", map[string]interface{}{
				"total": ptrType.GetTotal(),
			})
		}

		// Log details to help debug the actual type
		tflog.Error(ctx, "Type assertion failed for ListConnectors response", map[string]interface{}{
			"expected": "interface with GetTotal() int64 and GetData() []resconn.ConnectorResponse",
			"actual":   fmt.Sprintf("%T", agents),
		})

		return fmt.Errorf("unexpected response type from ListConnectors: %T", agents)
	}

	totalAgents := int(agentsList.GetTotal())

	tflog.Debug(ctx, "Received connector agents response", map[string]interface{}{
		"total_agents": totalAgents,
		"filters":      filters,
	})

	if totalAgents == 0 {
		return fmt.Errorf("no connector agent matching filter '%s' found", filters)
	}

	if totalAgents > 1 {
		return retry.Unrecoverable(fmt.Errorf("filter %s matches multiple agents (%d)", filters, totalAgents))
	}

	// Process the single agent found
	for _, agent := range agentsList.GetData() {
		respString, _ := json.Marshal(agent)
		tflog.Debug(ctx, "Found resource connector agent", map[string]interface{}{
			"agent_data": string(respString),
		})

		state := *data
		state.LoadFromAPI(ctx, agent)
		r.Synchronize(ctx, &state, data)
		*data = state

		tflog.Info(ctx, "Successfully configured resource connector agent", map[string]interface{}{
			"agent_id": state.ID.ValueInt64(),
		})
		return nil
	}

	return nil
}

// LoadFromAPI populates the model from API response data
func (r *resourceConnectorAgentResourceModel) LoadFromAPI(ctx context.Context, agent resconn.ConnectorResponse) {
	agentString, err := json.Marshal(agent)
	if err == nil {
		tflog.Debug(ctx, "Loading RC Agent from upstream", map[string]interface{}{
			"agent_data": string(agentString),
		})
	}

	r.ID = types.Int64Value(*agent.Id)
	r.Hostname = types.StringValue(*agent.Hostname)
	r.InstanceID = types.StringValue(*agent.InstanceId)
	r.Status = types.StringValue(*agent.Status)
	r.Confirmed = types.BoolValue(*agent.Confirmed)
	r.Enabled = types.BoolValue(*agent.Enabled)
}

func (r *resourceConnectorAgentResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data resourceConnectorAgentResourceModel

	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	agentID := data.ID.ValueInt64()
	tflog.Debug(ctx, "Reading resource connector agent", map[string]interface{}{
		"agent_id": agentID,
	})

	// Read API call logic with retry
	err := retry.Do(
		func() error {
			agent, httpRes, err := r.client.ConnectorsAPI.GetConnector(ctx, agentID).Execute()

			if httpRes != nil {
				switch httpRes.StatusCode {
				case connectorHTTPNotFound:
					tflog.Info(ctx, "Resource connector agent not found, removing from state", map[string]interface{}{
						"agent_id": agentID,
					})
					resp.State.RemoveResource(ctx)
					return nil
				case connectorHTTPTooManyReqs:
					return fmt.Errorf("too many requests (status %d)", httpRes.StatusCode)
				case connectorHTTPOK:
					// Success case - continue processing
				default:
					if err != nil {
						return retry.Unrecoverable(fmt.Errorf("non-retryable error (status %d): %v", httpRes.StatusCode, err))
					}
				}
			}

			if err != nil {
				return retry.Unrecoverable(err)
			}

			state := data
			state.LoadFromAPI(ctx, *agent)

			// Save updated data into Terraform state
			resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)

			tflog.Debug(ctx, "Successfully read resource connector agent", map[string]interface{}{
				"agent_id": agentID,
				"status":   state.Status.ValueString(),
			})
			return nil
		},
		retry.Attempts(connectorRetryMaxAttempts),
		retry.Delay(connectorRetryBaseDelay),
		retry.Context(ctx),
	)

	if err != nil {
		resp.Diagnostics.AddError(
			"Could not retrieve resource connector agent config",
			fmt.Sprintf("Failed to read resource connector agent %d: %v", agentID, err),
		)
	}
}

func (r *resourceConnectorAgentResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan resourceConnectorAgentResourceModel
	var state resourceConnectorAgentResourceModel

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)

	if resp.Diagnostics.HasError() {
		return
	}

	agentID := state.ID.ValueInt64()
	tflog.Info(ctx, "Updating resource connector agent", map[string]interface{}{
		"agent_id": agentID,
	})

	// Update API call logic
	r.Synchronize(ctx, &state, &plan)

	// Save updated data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)

	tflog.Debug(ctx, "Successfully updated resource connector agent state", map[string]interface{}{
		"agent_id": agentID,
	})
}

// Synchronize updates the resource connector agent based on plan changes
func (r *resourceConnectorAgentResource) Synchronize(ctx context.Context, state *resourceConnectorAgentResourceModel, plan *resourceConnectorAgentResourceModel) {
	agentID := state.ID.ValueInt64()

	// Update confirmed status if changed
	if plan.Confirmed.ValueBool() && plan.Confirmed.ValueBool() != state.Confirmed.ValueBool() {
		tflog.Debug(ctx, "Updating resource connector agent confirmed status", map[string]interface{}{
			"agent_id":  agentID,
			"confirmed": plan.Confirmed.ValueBool(),
		})

		if err := r.patchConnectorField(ctx, agentID, connectorPatchPathConfirmed, plan.Confirmed.ValueBoolPointer()); err != nil {
			tflog.Error(ctx, "Failed to update resource connector agent confirmed status", map[string]interface{}{
				"agent_id": agentID,
				"error":    err.Error(),
			})
		} else {
			state.Confirmed = plan.Confirmed
			tflog.Debug(ctx, "Successfully updated confirmed status")
		}
	}

	// Update enabled status if changed
	if plan.Enabled.ValueBool() && plan.Enabled.ValueBool() != state.Enabled.ValueBool() {
		tflog.Debug(ctx, "Updating resource connector agent enabled status", map[string]interface{}{
			"agent_id": agentID,
			"enabled":  plan.Enabled.ValueBool(),
		})

		if err := r.patchConnectorField(ctx, agentID, connectorPatchPathEnabled, plan.Enabled.ValueBoolPointer()); err != nil {
			tflog.Error(ctx, "Failed to update resource connector agent enabled status", map[string]interface{}{
				"agent_id": agentID,
				"error":    err.Error(),
			})
		} else {
			state.Enabled = plan.Enabled
			tflog.Debug(ctx, "Successfully updated enabled status")
		}
	}
}

// patchConnectorField updates a single field on the connector using PATCH operation
func (r *resourceConnectorAgentResource) patchConnectorField(ctx context.Context, agentID int64, path string, value *bool) error {
	op := resconn.Op(connectorPatchOpReplace)
	req := resconn.ConnectorPatchReqInner{
		Op:    &op,
		Path:  &path,
		Value: value,
	}
	reqs := []resconn.ConnectorPatchReqInner{req}

	_, _, err := r.client.ConnectorsAPI.PatchConnector(ctx, agentID).ConnectorPatchReqInner(reqs).Execute()
	return err
}

// Delete deletes the resource connector agent and removes the Terraform state on success.
func (r *resourceConnectorAgentResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data resourceConnectorAgentResourceModel

	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	agentID := data.ID.ValueInt64()
	tflog.Info(ctx, "Deleting resource connector agent", map[string]interface{}{
		"agent_id": agentID,
	})

	// Delete API call logic with retry
	err := retry.Do(
		func() error {
			_, httpRes, err := r.client.ConnectorsAPI.DeleteConnector(ctx, agentID).Execute()

			if httpRes != nil {
				switch httpRes.StatusCode {
				case connectorHTTPTooManyReqs:
					return fmt.Errorf("too many requests (status %d)", httpRes.StatusCode)
				case connectorHTTPNotFound:
					tflog.Debug(ctx, "Resource connector agent not found, already deleted")
					return nil
				}
			}

			if err != nil {
				return retry.Unrecoverable(fmt.Errorf("failed to delete connector: %w", err))
			}

			tflog.Info(ctx, "Successfully deleted resource connector agent", map[string]interface{}{
				"agent_id": agentID,
			})
			return nil
		},
		retry.Attempts(connectorRetryMaxAttempts),
		retry.Delay(connectorRetryBaseDelay),
		retry.Context(ctx),
	)

	if err != nil {
		resp.Diagnostics.AddError(
			"Error deleting resource connector agent",
			fmt.Sprintf("Could not delete resource connector agent %d: %v", agentID, err),
		)
	}
}

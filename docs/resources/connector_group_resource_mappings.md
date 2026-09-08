---
page_title: "ciscosecureaccess_connector_group_resource_mappings Resource - terraform-provider-ciscosecureaccess"
subcategory: ""
description: |-
  Additively manages private-resource mappings for an existing Resource Connector Group.
---

# ciscosecureaccess_connector_group_resource_mappings (Resource)

Additively manages private-resource mappings for an existing Resource Connector Group. Existing mappings that are not listed in this resource are preserved. Destroying the Terraform resource removes only the mappings it managed.

The API key requires the `deployments.resourceconnectors:read` and `deployments.resourceconnectors:write` scopes.

## Example Usage

```terraform
data "ciscosecureaccess_resource_connector" "example" {
  filter = {
    name  = "name"
    query = "example-connector-group"
  }
}

resource "ciscosecureaccess_connector_group_resource_mappings" "example" {
  connector_group_id = data.ciscosecureaccess_resource_connector.example.resource_connector_groups[0].id
  resource_ids = [
    ciscosecureaccess_private_resource.example.id,
  ]
}
```

## Schema

### Required

- `connector_group_id` (Number) ID of the existing Resource Connector Group.
- `resource_ids` (Set of Number) IDs of private resources to map to the Resource Connector Group. Other existing mappings are preserved.

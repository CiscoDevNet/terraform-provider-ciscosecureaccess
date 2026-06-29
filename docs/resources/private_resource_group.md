---
page_title: "ciscosecureaccess_private_resource_group Resource - terraform-provider-ciscosecureaccess"
subcategory: ""
description: |-
  Manages a Cisco Secure Access private resource group.
---

# ciscosecureaccess_private_resource_group (Resource)

Manages a Cisco Secure Access private resource group and its private-resource membership.

Deletion is non-forced. Remove policy references before destroying a referenced group.

## Example Usage

```terraform
resource "ciscosecureaccess_private_resource_group" "example" {
  name         = "Engineering Applications"
  description  = "Private resources used by the engineering team"
  resource_ids = []
}
```

## Schema

### Required

- `name` (String) Name of the private resource group. Only letters, numbers, spaces, and hyphens are allowed.
- `resource_ids` (Set of Number) IDs of private resources that belong to the group. The set may be empty.

### Optional

- `description` (String) Description of the private resource group.

### Read-Only

- `created_at` (String) Creation timestamp returned by the API.
- `id` (Number) Unique ID of the private resource group.
- `modified_at` (String) Last-modified timestamp returned by the API.

## Import

Import a private resource group with its numeric ID:

```shell
terraform import ciscosecureaccess_private_resource_group.example 12345
```

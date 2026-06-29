---
page_title: "ciscosecureaccess_application_list Resource - terraform-provider-ciscosecureaccess"
subcategory: ""
description: |-
  Manages a Cisco Secure Access application list.
---

# ciscosecureaccess_application_list (Resource)

Manages a custom Cisco Secure Access application list. Names must be unique within the organization. Cisco-managed default lists can be imported for inspection but cannot be updated or deleted by this resource.

Application IDs are numeric in the application-list API. Resolve application and application-category names in the target organization with the provider data sources before assigning membership.

## Example Usage

```terraform
data "ciscosecureaccess_application" "slack" {
  name = "Slack"
  type = "AVC"
}

data "ciscosecureaccess_application_category" "collaboration" {
  name = "Collaboration"
}

resource "ciscosecureaccess_application_list" "collaboration" {
  name = "Engineering Collaboration Applications"

  application_ids = [
    data.ciscosecureaccess_application.slack.id,
  ]
  application_category_ids = [
    data.ciscosecureaccess_application_category.collaboration.id,
  ]
}
```

## Schema

### Required

- `name` (String) Application list display name. Names must be unique within the organization.

### Optional

- `application_category_ids` (Set of Number) Application category IDs included in the list. Defaults to an empty set.
- `application_ids` (Set of Number) Application IDs included in the list. Defaults to an empty set.

### Read-Only

- `created_at` (String) Creation timestamp returned by the API.
- `id` (Number) Unique ID of the application list.
- `is_default` (Boolean) Whether this is a Cisco-managed default list.
- `modified_at` (String) Last-modified timestamp returned by the API.
- `organization_id` (Number) Organization ID returned by the application-list API, when available.

## Import

Import an application list with its numeric ID:

```shell
terraform import ciscosecureaccess_application_list.example 12345
```

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

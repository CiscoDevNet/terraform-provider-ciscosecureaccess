# List of all groups matching string "us-west-2"
data "ciscosecureaccess_resource_connector" "groups" {
    filter =  {
        name = "name"
        query = "us-west-2"
    }
}

# List of single group matching string "unique-group"
data "ciscosecureaccess_resource_connector" "groups" {
    filter =  {
        name = "name"
        query = "unique-group"
    lifecycle {
      postcondition {
        condition = length(self.resource_connector_groups) != 0
        error_message = "Connector Group unique-group could not be found, or matched multiple groups"
      }
}

# Fail the deployment if provisioning key is expired
data "ciscosecureaccess_resource_connector" "groups" {
    filter =  {
        name = "name"
        query = "unique-group"
    }
    lifecycle {
      postcondition {
        condition = timecmp(self.resource_connector_groups[0].key_expires_at, plantimestamp()) > 0
        error_message = "Connector Group unique-group has an expired provisioning key"
      }

      postcondition {
        condition = length(self.resource_connector_groups) != 0
        error_message = "Connector Group unique-group could not be found, or matched multiple groups"
      }
    }
}


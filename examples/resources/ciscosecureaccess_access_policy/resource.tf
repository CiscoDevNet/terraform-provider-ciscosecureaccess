# Allow access by all identities matching "remoteuser" to new private resource
resource "ciscosecureaccess_access_policy" "remote_to_pa" {
    name = "remote-user-private-app"
    action = "allow"
    enabled = "true"
    log_level = "LOG_ALL"
    traffic_type = "PRIVATE_NETWORK"
    source_ids = [for s in data.ciscosecureaccess_identity.remote_identity.identities : s.label]
    private_resource_ids = [resource.ciscosecureaccess_private_resource.new_resource.id]
    description = "Test rule for terraform access policy support"
}

data "ciscosecureaccess_identity" "remote_identity" {
  filter = "remoteuser"
}

resource "ciscosecureaccess_private_resource" "new_resource" {
...
}

# Allow every source to reach a private resource while applying the
# organization's default client posture profile.
resource "ciscosecureaccess_access_policy" "all_sources_with_posture" {
  name                      = "all-sources-private-app"
  action                    = "allow"
  enabled                   = true
  log_level                 = "LOG_ALL"
  traffic_type              = "PRIVATE_NETWORK"
  source_all                = true
  private_resource_ids      = [ciscosecureaccess_private_resource.new_resource.id]
  client_posture_profile_id = 0
}

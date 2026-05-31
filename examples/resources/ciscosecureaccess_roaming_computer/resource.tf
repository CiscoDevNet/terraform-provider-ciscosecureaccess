# Roaming computers must be imported, not created.
# First import an existing roaming computer by its device_id:
# terraform import ciscosecureaccess_roaming_computer.example abc123def456

resource "ciscosecureaccess_roaming_computer" "example" {
  name = "laptop-corp-001"
}

resource "ciscosecureaccess_internal_network" "example" {
  name          = "my-internal-network"
  ip_address    = "198.51.100.0"
  prefix_length = 24
  site_id       = 1234
}

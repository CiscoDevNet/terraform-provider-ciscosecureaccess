resource "ciscosecureaccess_network" "example" {
  name          = "corporate-network"
  ip_address    = "192.0.2.0"
  prefix_length = 29
  is_dynamic    = false
  status        = "OPEN"
}

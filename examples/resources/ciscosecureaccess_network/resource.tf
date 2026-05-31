resource "ciscosecureaccess_network" "example" {
  name          = "corporate-network"
  ip_address    = "10.0.0.0"
  prefix_length = 8
  is_dynamic    = false
  status        = "OPEN"
}

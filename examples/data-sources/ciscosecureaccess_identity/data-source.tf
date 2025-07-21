# A list of identities that match the string "devengineer"
data "ciscosecureaccess_identity" "identity" {
  filter = "devengineer"
}

output "identity_out" {
  value = [for s in data.ciscosecureaccess_identity.identity.identities : s.label]
}

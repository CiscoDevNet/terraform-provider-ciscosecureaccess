data "ciscosecureaccess_activity_report" "example" {
  from    = "2024-01-01T00:00:00Z"
  to      = "2024-01-02T00:00:00Z"
  limit   = 100
  verdict = "blocked"
}

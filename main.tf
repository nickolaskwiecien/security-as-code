module "aws-managed-rules" {
  source = "./aws-managed-rules"
}

module "cc-guardduty" {
  source = "./cc-guardduty"
}

variable "region" {
  description = "The region you would like to deploy in. Default us-east-1"
}
variable "iam_profile" {
  description = "the iam profile asssociated with the account you would like to deploy in"
  default = ["us-east-1"]
}

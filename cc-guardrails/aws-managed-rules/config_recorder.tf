resource "aws_config_configuration_recorder" "cc_config_recorder" {
  name     = "cc_config_recorder"
  role_arn = "${aws_iam_role.config_recorder_role.arn}"
}

resource "aws_iam_role" "config_recorder_role" {
  name = "config_recorder_role"

  assume_role_policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "config.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
POLICY
}

resource "aws_iam_policy" "config_policy" {
  name        = "config_policy"
  description = "permssions for AWS config, allows terraform to assume role and enable config rules"

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "config:Put*"
      ],
      "Effect": "Allow",
      "Resource": "*"
    }
  ]
}
EOF
}

resource "aws_iam_role_policy_attachment" "policy-attach" {
  role       = "${aws_iam_role.config_recorder_role.name}"
  policy_arn = "${aws_iam_policy.config_policy.arn}"
}

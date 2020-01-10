
# Analytics 
resource "aws_config_config_rule" "ELASTICACHE_REDIS_CLUSTER_AUTOMATIC_BACKUP_CHECK" {
  depends_on = ["aws_config_configuration_recorder.cc_config_recorder"]

  description = "Check if the Amazon ElastiCache Redis clusters have automatic backup turned on. The rule is NON_COMPLIANT if the SnapshotRetentionLimit for Redis cluster is less than the SnapshotRetentionPeriod parameter. For example: If the parameter is 15 then the rule is non-compliant if the snapshotRetentionPeriod is between 0-15."

  name            = "ELASTICACHE_REDIS_CLUSTER_AUTOMATIC_BACKUP_CHECK"
  source {
    owner             = "AWS"
    source_identifier = "ELASTICACHE_REDIS_CLUSTER_AUTOMATIC_BACKUP_CHECK"
  }


  # (Optional) Minimum snapshot retention period in days for Redis cluster. The default is 15 days.
  # SNAPSHOT_RETENTION_PERIOD = ["snapshot_retention_period"]

}


resource "aws_config_config_rule" "ELASTICSEARCH_ENCRYPTED_AT_REST" {
  description = "Checks whether Amazon Elasticsearch Service (Amazon ES) domains have encryption at rest configuration enabled. The rule is NON_COMPLIANT if the EncryptionAtRestOptions field is not enabled."

  name = "ELASTICSEARCH_ENCRYPTED_AT_REST"
 maximum_execution_frequency = "TwentyFour_Hours"
  source {
    owner             = "AWS"
    source_identifier = "ELASTICSEARCH_ENCRYPTED_AT_REST"
  }
  depends_on = ["aws_config_configuration_recorder.cc_config_recorder"]



}

resource "aws_config_config_rule" "ELASTICSEARCH_IN_VPC_ONLY" {
  depends_on = ["aws_config_configuration_recorder.cc_config_recorder"]

  description = "Checks whether Amazon Elasticsearch Service (Amazon ES) domains are in Amazon Virtual Private Cloud (Amazon VPC). The rule is NON_COMPLIANT if the Amazon ES domain endpoint is public."

  name            = "ELASTICSEARCH_IN_VPC_ONLY"
  source {
    owner             = "AWS"
    source_identifier = "ELASTICSEARCH_IN_VPC_ONLY"
  }



}

# Compute 
resource "aws_config_config_rule" "APPROVED_AMIS_BY_ID" {
  depends_on = ["aws_config_configuration_recorder.cc_config_recorder"]

  description = "Checks whether running instances are using specified AMIs. Specify a list of approved AMI IDs. Running instances with AMIs that are not on this list are NON_COMPLIANT."

  name            = "APPROVED_AMIS_BY_ID"
  source {
    owner             = "AWS"
    source_identifier = "APPROVED_AMIS_BY_ID"
  }


  # The AMI IDs (comma-separated list of up to 10).
  ami_ids = ["ami_ids"]

}

resource "aws_config_config_rule" "APPROVED_AMIS_BY_TAG" {
  depends_on = ["aws_config_configuration_recorder.cc_config_recorder"]

  description = "Checks whether running instances are using specified AMIs. Specify the tags that identify the AMIs. Running instances with AMIs that don't have at least one of the specified tags are NON_COMPLIANT."

  name            = "APPROVED_AMIS_BY_TAG"
  source {
    owner             = "AWS"
    source_identifier = "APPROVED_AMIS_BY_TAG"
  }


  # The AMIs by tag (comma-separated list up to 10; for example, "tag-key:tag-value").
  # amis_by_tag_key_and_value = ["amis_by_tag_key_and_value"]

}

resource "aws_config_config_rule" "AUTOSCALING_GROUP_ELB_HEALTHCHECK_REQUIRED" {
  depends_on = ["aws_config_configuration_recorder.cc_config_recorder"]

  description = "Checks whether your Auto Scaling groups that are associated with a load balancer are using Elastic Load Balancing health checks."

  name            = "AUTOSCALING_GROUP_ELB_HEALTHCHECK_REQUIRED"
  source {
    owner             = "AWS"
    source_identifier = "AUTOSCALING_GROUP_ELB_HEALTHCHECK_REQUIRED"
  }


}

resource "aws_config_config_rule" "DESIRED_INSTANCE_TENANCY" {
  depends_on = ["aws_config_configuration_recorder.cc_config_recorder"]

  description = "Checks instances for specified tenancy. Specify AMI IDs to check instances that are launched from those AMIs or specify host IDs to check whether instances are launched on those Dedicated Hosts. Separate multiple ID values with commas."

  name            = "DESIRED_INSTANCE_TENANCY"
  source {
    owner             = "AWS"
    source_identifier = "DESIRED_INSTANCE_TENANCY"
  }


  # The desired tenancy of the instances. Valid values are DEDICATED, HOST, and DEFAULT.
  # tenancy = ["tenancy"]

  # The rule evaluates instances launched only from the AMI with the specified ID. Separate multiple AMI IDs with commas.
  # image_id = ["image_id"]

  # The ID of the Amazon EC2 Dedicated Host on which the instances are meant to be launched. Separate multiple host IDs with commas.
  # host_id = ["host_id"]

}

resource "aws_config_config_rule" "DESIRED_INSTANCE_TYPE" {
  depends_on = ["aws_config_configuration_recorder.cc_config_recorder"]

  description = "Checks whether your EC2 instances are of the specified instance types."

  name            = "DESIRED_INSTANCE_TYPE"
  source {
    owner             = "AWS"
    source_identifier = "DESIRED_INSTANCE_TYPE"
  }


  # Comma-separated list of EC2 instance types (for example, "t2.small, m4.large, i2.xlarge").
  # instance_type = ["instance_type"]

}

resource "aws_config_config_rule" "EBS_OPTIMIZED_INSTANCE" {
  depends_on = ["aws_config_configuration_recorder.cc_config_recorder"]

  description = "Checks whether EBS optimization is enabled for your EC2 instances that can be EBS-optimized."

  name            = "EBS_OPTIMIZED_INSTANCE"
  source {
    owner             = "AWS"
    source_identifier = "EBS_OPTIMIZED_INSTANCE"
  }


}

resource "aws_config_config_rule" "EC2_STOPPED_INSTANCE" {

  description = "Checks whether there are instances stopped for more than the allowed number of days. The instance is NON_COMPLIANT if the state of the ec2 instance has been stopped for longer than the allowed number of days."

  name            = "EC2_STOPPED_INSTANCE"
  maximum_execution_frequency = "TwentyFour_Hours"
 
  source {
    owner             = "AWS"
    source_identifier = "EC2_STOPPED_INSTANCE"
    
  }
  depends_on = ["aws_config_configuration_recorder.cc_config_recorder"]
   # (Optional) The number of days an ec2 instance can be stopped before it is NON_COMPLIANT. The default number of days is 30.

}
resource "aws_config_config_rule" "EC2_INSTANCE_DETAILED_MONITORING_ENABLED" {

  description = "Checks whether detailed monitoring is enabled for EC2 instances."

  name            = "EC2_INSTANCE_DETAILED_MONITORING_ENABLED"
source {
    owner             = "AWS"
    source_identifier = "EC2_INSTANCE_DETAILED_MONITORING_ENABLED"
  }
    depends_on = ["aws_config_configuration_recorder.cc_config_recorder"]


}

resource "aws_config_config_rule" "EC2_INSTANCE_MANAGED_BY_SSM" {
  depends_on = ["aws_config_configuration_recorder.cc_config_recorder"]

  description = "Checks whether the Amazon EC2 instances in your account are managed by AWS Systems Manager."

  name            = "EC2_INSTANCE_MANAGED_BY_SSM"
  source {
    owner             = "AWS"
    source_identifier = "EC2_INSTANCE_MANAGED_BY_SSM"
  }


}

resource "aws_config_config_rule" "EC2_INSTANCE_NO_PUBLIC_IP" {
  depends_on = ["aws_config_configuration_recorder.cc_config_recorder"]

  description = "Checks whether Amazon Elastic Compute Cloud (Amazon EC2) instances have a public IP association. The rule is NON_COMPLIANT if the publicIp field is present in the Amazon EC2 instance configuration item. This rule applies only to IPv4."

  name            = "EC2_INSTANCE_NO_PUBLIC_IP"
  source {
    owner             = "AWS"
    source_identifier = "EC2_INSTANCE_NO_PUBLIC_IP"
  }


}

resource "aws_config_config_rule" "INSTANCES_IN_VPC" {
  depends_on = ["aws_config_configuration_recorder.cc_config_recorder"]

  description = "Checks whether your EC2 instances belong to a virtual private cloud (VPC). Optionally, you can specify the VPC ID to associate with your instances."

  name            = "INSTANCES_IN_VPC"
  source {
    owner             = "AWS"
    source_identifier = "INSTANCES_IN_VPC"
  }


  # The ID of the VPC that contains these instances.
  # vpc_id = ["vpc_id"]

}

resource "aws_config_config_rule" "EC2_MANAGEDINSTANCE_APPLICATIONS_BLACKLISTED" {
  depends_on = ["aws_config_configuration_recorder.cc_config_recorder"]

  description = "Checks that none of the specified applications are installed on the instance. Optionally, specify the application version. Newer versions of the application will not be blacklisted. You can also specify the platform to apply the rule only to instances running that platform."

  name            = "EC2_MANAGEDINSTANCE_APPLICATIONS_BLACKLISTED"
  source {
    owner             = "AWS"
    source_identifier = "EC2_MANAGEDINSTANCE_APPLICATIONS_BLACKLISTED"
  }


  # Comma-separated list of application names. Optionally, specify versions appended with ":" (for example, "Chrome:0.5.3, FireFox").
  # application_names = ["application_names"]

  # The platform type (for example, "Linux" or "Windows").
  # platform_type = ["platform_type"]

}

resource "aws_config_config_rule" "EC2_MANAGEDINSTANCE_APPLICATIONS_REQUIRED" {
  depends_on = ["aws_config_configuration_recorder.cc_config_recorder"]

  description = "Checks whether all of the specified applications are installed on the instance. Optionally, specify the minimum acceptable version. You can also specify the platform to apply the rule only to instances running that platform."

  name            = "EC2_MANAGEDINSTANCE_APPLICATIONS_REQUIRED"
  source {
    owner             = "AWS"
    source_identifier = "EC2_MANAGEDINSTANCE_APPLICATIONS_REQUIRED"
  }


  # Comma-separated list of application names. Optionally, specify versions appended with ":" (for example, "Chrome:0.5.3, FireFox").
  # application_names = ["application_names"]

  # The platform type (for example, "Linux" or "Windows"). 
  # platform_type = ["platform_type"]

}

resource "aws_config_config_rule" "EC2_MANAGEDINSTANCE_ASSOCIATION_COMPLIANCE_STATUS_CHECK" {
  depends_on = ["aws_config_configuration_recorder.cc_config_recorder"]

  description = "Checks whether the compliance status of the Amazon EC2 Systems Manager association compliance is COMPLIANT or NON_COMPLIANT after the association execution on the instance. The rule is COMPLIANT if the field status is COMPLIANT."

  name            = "EC2_MANAGEDINSTANCE_ASSOCIATION_COMPLIANCE_STATUS_CHECK"
  source {
    owner             = "AWS"
    source_identifier = "EC2_MANAGEDINSTANCE_ASSOCIATION_COMPLIANCE_STATUS_CHECK"
  }


}

resource "aws_config_config_rule" "EC2_MANAGEDINSTANCE_INVENTORY_BLACKLISTED" {
  depends_on = ["aws_config_configuration_recorder.cc_config_recorder"]

  description = "Checks whether instances managed by AWS Systems Manager are configured to collect blacklisted inventory types."

  name            = "EC2_MANAGEDINSTANCE_INVENTORY_BLACKLISTED"
  source {
    owner             = "AWS"
    source_identifier = "EC2_MANAGEDINSTANCE_INVENTORY_BLACKLISTED"
  }


  # Comma-separated list of Systems Manager inventory types (for example, "AWS:Network, AWS:WindowsUpdate").
  # inventory_names = ["inventory_names"]

  # Platform type (for example, “Linux”).
  # platform_tpye = ["platform_type"]

}

resource "aws_config_config_rule" "EC2_MANAGEDINSTANCE_PATCH_COMPLIANCE_STATUS_CHECK" {
  depends_on = ["aws_config_configuration_recorder.cc_config_recorder"]

  description = "Checks whether the compliance status of the Amazon EC2 Systems Manager patch compliance is COMPLIANT or NON_COMPLIANT after the patch installation on the instance. The rule is COMPLIANT if the field status is COMPLIANT."

  name            = "EC2_MANAGEDINSTANCE_PATCH_COMPLIANCE_STATUS_CHECK"
  source {
    owner             = "AWS"
    source_identifier = "EC2_MANAGEDINSTANCE_PATCH_COMPLIANCE_STATUS_CHECK"
  }


}

resource "aws_config_config_rule" "EC2_MANAGEDINSTANCE_PLATFORM_CHECK" {
  depends_on = ["aws_config_configuration_recorder.cc_config_recorder"]

  description = "Checks whether EC2 managed instances have the desired configurations."

  name            = "EC2_MANAGEDINSTANCE_PLATFORM_CHECK"
  source {
    owner             = "AWS"
    source_identifier = "EC2_MANAGEDINSTANCE_PLATFORM_CHECK"
  }


  # The version of the agent (for example, "2.0.433.0").
  # agent_version = ["agent_version"]

  # The platform type (for example, "Linux" or "Windows").
  # platform_tyoe = ["platform_type"]

  # The version of the platform (for example, "2016.09").
  # platform_version = ["platform_version"]

}

resource "aws_config_config_rule" "EC2_SECURITY_GROUP_ATTACHED_TO_ENI" {
  depends_on = ["aws_config_configuration_recorder.cc_config_recorder"]

  description = "Checks that security groups are attached to Amazon Elastic Compute Cloud (Amazon EC2) instances or to an elastic network interface. The rule returns NON_COMPLIANT if the security group is not associated with an Amazon EC2 instance or an elastic network interface."

  name            = "EC2_SECURITY_GROUP_ATTACHED_TO_ENI"
  source {
    owner             = "AWS"
    source_identifier = "EC2_SECURITY_GROUP_ATTACHED_TO_ENI"
  }


}

resource "aws_config_config_rule" "EC2_VOLUME_INUSE_CHECK" {
  depends_on = ["aws_config_configuration_recorder.cc_config_recorder"]

  description = "Checks whether EBS volumes are attached to EC2 instances. Optionally checks if EBS volumes are marked for deletion when an instance is terminated."

  name            = "EC2_VOLUME_INUSE_CHECK"
  source {
    owner             = "AWS"
    source_identifier = "EC2_VOLUME_INUSE_CHECK"
  }


  # EBS volumes are marked for deletion when an instance is terminated.
  # delete_on_termination = ["delete_on_termination"]

}

resource "aws_config_config_rule" "EIP_ATTACHED" {
  depends_on = ["aws_config_configuration_recorder.cc_config_recorder"]

  description = "Checks whether all Elastic IP addresses that are allocated to a VPC are attached to EC2 instances or in-use elastic network interfaces (ENIs)."

  name            = "EIP_ATTACHED"
  source {
    owner             = "AWS"
    source_identifier = "EIP_ATTACHED"
  }


}

resource "aws_config_config_rule" "ELB_ACM_CERTIFICATE_REQUIRED" {
  depends_on = ["aws_config_configuration_recorder.cc_config_recorder"]

  description = "Checks whether the Classic Load Balancers use SSL certificates provided by AWS Certificate Manager. To use this rule, use an SSL or HTTPS listener with your Classic Load Balancer. This rule is only applicable to Classic Load Balancers. This rule does not check Application Load Balancers and Network Load Balancers."

  name            = "ELB_ACM_CERTIFICATE_REQUIRED"
  source {
    owner             = "AWS"
    source_identifier = "ELB_ACM_CERTIFICATE_REQUIRED"
  }


}

resource "aws_config_config_rule" "ELB_CUSTOM_SECURITY_POLICY_SSL_CHECK" {
  depends_on = ["aws_config_configuration_recorder.cc_config_recorder"]

  description = "Checks whether your Classic Load Balancer SSL listeners are using a custom policy. The rule is only applicable if there are SSL listeners for the Classic Load Balancer."

  name            = "ELB_CUSTOM_SECURITY_POLICY_SSL_CHECK"
  source {
    owner             = "AWS"
    source_identifier = "ELB_CUSTOM_SECURITY_POLICY_SSL_CHECK"
  }


  # Comma-separated list of ciphers and protocol.
  # ssl_protocols_and_ciphers = ["ssl_protocols_and_ciphers"]

}

resource "aws_config_config_rule" "ELB_LOGGING_ENABLED" {
  depends_on = ["aws_config_configuration_recorder.cc_config_recorder"]

  description = "Checks whether the Application Load Balancers and the Classic Load Balancers have logging enabled. The rule is NON_COMPLIANT if the access_logs.s3.enabled is false or access_logs.S3.bucket is not equal to the s3BucketName that you provided."

  name            = "ELB_LOGGING_ENABLED"
  source {
    owner             = "AWS"
    source_identifier = "ELB_LOGGING_ENABLED"
  }


  # (optional) Comma-separated list of Amazon S3 bucket names for Elastic Load Balancing to deliver the log files. 
  # s3BucketsNames = ["s3_bucket_names"]

}

resource "aws_config_config_rule" "ELB_PREDEFINED_SECURITY_POLICY_SSL_CHECK" {
  depends_on = ["aws_config_configuration_recorder.cc_config_recorder"]

  description = "Checks whether your Classic Load Balancer SSL listeners are using a predefined policy. The rule is only applicable if there are SSL listeners for the Classic Load Balancer."

  name            = "ELB_PREDEFINED_SECURITY_POLICY_SSL_CHECK"
  source {
    owner             = "AWS"
    source_identifier = "ELB_PREDEFINED_SECURITY_POLICY_SSL_CHECK"
  }


  # Name of the predefined policy.
  # predefined_policy_name = ["predefined_policy_name"]

}

resource "aws_config_config_rule" "ENCRYPTED_VOLUMES" {
  depends_on = ["aws_config_configuration_recorder.cc_config_recorder"]

  description = "Checks whether the EBS volumes that are in an attached state are encrypted. If you specify the ID of a KMS key for encryption using the kmsId parameter, the rule checks if the EBS volumes in an attached state are encrypted with that KMS key."

  name            = "ENCRYPTED_VOLUMES"
  source {
    owner             = "AWS"
    source_identifier = "ENCRYPTED_VOLUMES"
  }


  #ID or ARN of the KMS key that is used to encrypt the volume.
  # kms_id = ["kms_id"]

}

resource "aws_config_config_rule" "LAMBDA_CONCURRENCY_CHECK" {
  depends_on = ["aws_config_configuration_recorder.cc_config_recorder"]

  description = "Checks whether the AWS Lambda function is configured with function-level concurrent execution limit. The rule is NON_COMPLIANT if the Lambda function is not configured with function-level concurrent execution limit."

  name            = "LAMBDA_CONCURRENCY_CHECK"
  source {
    owner             = "AWS"
    source_identifier = "LAMBDA_CONCURRENCY_CHECK"
  }


  # (Optional) Minimum concurrency execution limit
  # cocurrency_limit_low = ["cocurrency_limit_low"]

  #(Optional) Maximum concurrency execution limit
  # cocurrency_limit_high = ["cocurrency_limit_high"]



}

resource "aws_config_config_rule" "LAMBDA_DLQ_CHECK" {
  depends_on = ["aws_config_configuration_recorder.cc_config_recorder"]

  description = "Checks whether an AWS Lambda function is configured with a dead-letter queue. The rule is NON_COMPLIANT if the Lambda function is not configured with a dead-letter queue."

  name            = "LAMBDA_DLQ_CHECK"
  source {
    owner             = "AWS"
    source_identifier = "LAMBDA_DLQ_CHECK"
  }


  # (Optional) Comma-separated list of Amazon SQS and Amazon SNS ARNs that must be configured as the Lambda function dead-letter queue target.
  # dlq_arns = ["dlq_arns"]

}

resource "aws_config_config_rule" "LAMBDA_FUNCTION_SETTINGS_CHECK" {
  depends_on = ["aws_config_configuration_recorder.cc_config_recorder"]

  description = "Checks that the lambda function settings for runtime, role, timeout, and memory size match the expected values."

  name            = "LAMBDA_FUNCTION_SETTINGS_CHECK"
  source {
    owner             = "AWS"
    source_identifier = "LAMBDA_FUNCTION_SETTINGS_CHECK"
  }


  # Comma-separated list of runtime values.
  # runtime = ["runtime"]

  # IAM role
  # role = ["role"]

  # Timeout in seconds 
  # timeout = ["timeout"]

  # Memory Size in seconds 
  # memory_size = ["memory_size"]

}

resource "aws_config_config_rule" "LAMBDA_FUNCTION_PUBLIC_ACCESS_PROHIBITED" {
  depends_on = ["aws_config_configuration_recorder.cc_config_recorder"]

  description = "Checks whether the AWS Lambda function policy attached to the Lambda resource prohibits public access. If the Lambda function policy allows public access it is NON_COMPLIANT."

  name            = "LAMBDA_FUNCTION_PUBLIC_ACCESS_PROHIBITED"
  source {
    owner             = "AWS"
    source_identifier = "LAMBDA_FUNCTION_PUBLIC_ACCESS_PROHIBITED"
  }


}

resource "aws_config_config_rule" "LAMBDA_INSIDE_VPC" {
  depends_on = ["aws_config_configuration_recorder.cc_config_recorder"]

  description = "Checks whether an AWS Lambda function is in an Amazon Virtual Private Cloud. The rule is NON_COMPLIANT if the Lambda function is not in a VPC."

  name            = "LAMBDA_INSIDE_VPC"
  source {
    owner             = "AWS"
    source_identifier = "LAMBDA_INSIDE_VPC"
  }


  # (Optional) Comma-separated list of subnet IDs that Lambda functions must be associated with.
  # subnet_Id = ["subnet_id"]

}

resource "aws_config_config_rule" "RESTRICTED_INCOMING_TRAFFIC" {
  depends_on = ["aws_config_configuration_recorder.cc_config_recorder"]

  description = "Checks whether the incoming SSH traffic for the security groups is accessible to the specified ports. The rule is COMPLIANT when the IP addresses of the incoming SSH traffic in the security group are restricted to the specified ports. This rule applies only to IPv4."

  name            = "RESTRICTED_INCOMING_TRAFFIC"
  source {
    owner             = "AWS"
    source_identifier = "RESTRICTED_INCOMING_TRAFFIC"
  }


  # Blocked TCP port number.
  # blocked_port_1 = ["blocked_port_1"]

  # Blocked TCP port number.
  # blocked_port_2 = ["blocked_port_2"]

  # Blocked TCP port number.
  # blocked_port_3 = ["blocked_port_3"]

  # Blocked TCP port number.
  # blocked_port_4 = ["blocked_port_4"]

  # Blocked TCP port number.
  # blocked_port_5 = ["blocked_port_5"]

  #Continue this format for as many blocked ports you as you need

}

resource "aws_config_config_rule" "INCOMING_SSH_DISABLED" {
  depends_on = ["aws_config_configuration_recorder.cc_config_recorder"]

  description = "Checks whether the incoming SSH traffic for the security groups is accessible. The rule is COMPLIANT when the IP addresses of the incoming SSH traffic in the security groups are restricted. This rule applies only to IPv4."

  name            = "INCOMING_SSH_DISABLED"
  source {
    owner             = "AWS"
    source_identifier = "INCOMING_SSH_DISABLED"
  }


}

# Crpytography and PKI

resource "aws_config_config_rule" "KMS_CMK_NOT_SCHEDULED_FOR_DELETION" {
  depends_on = ["aws_config_configuration_recorder.cc_config_recorder"]

  description = "Checks whether customer master keys (CMKs) are not scheduled for deletion in AWS Key Management Service (KMS). The rule is NON_COMPLIANT if CMKs are scheduled for deletion."

  name            = "KMS_CMK_NOT_SCHEDULED_FOR_DELETION"
  source {
    owner             = "AWS"
    source_identifier = "KMS_CMK_NOT_SCHEDULED_FOR_DELETION"
  }


  # Comma-separated list of specific customer managed key IDs not to be scheduled for deletion. If you do not specify any keys, the rule checks all the keys.
  # kms_key_ids = ["kms_key_ids"]

}

# Database 

resource "aws_config_config_rule" "DB_INSTANCE_BACKUP_ENABLED" {
  depends_on = ["aws_config_configuration_recorder.cc_config_recorder"]

  description = "DB_INSTANCE_BACKUP_ENABLED"

  name            = "DB_INSTANCE_BACKUP_ENABLED"
  source {
    owner             = "AWS"
    source_identifier = "DB_INSTANCE_BACKUP_ENABLED"
  }


  # Retention period for backups
  # backup_retention_period = ["backup_retention_period"]

  # Time range in which backups are created
  # preferred_backup_window = ["preferred_backup_window"]

  # Checks whether RDS DB instance have backups enabled for read replicas
  # check_read_replicas = ["check_read_replicas"]

}

resource "aws_config_config_rule" "DYNAMODB_AUTOSCALING_ENABLED" {
  depends_on = ["aws_config_configuration_recorder.cc_config_recorder"]

  description = "Checks whether Auto Scaling or On-Demand is enabled on your DynamoDB tables and/or global secondary indexes. Optionally you can set the read and write capacity units for the table or global secondary index."

  name            = "DYNAMODB_AUTOSCALING_ENABLED"
  source {
    owner             = "AWS"
    source_identifier = "DYNAMODB_AUTOSCALING_ENABLED"
  }


  # The minimum number of units that should be provisioned with read capacity in the Auto Scaling group.
  # min_provisioned_read_capacity = ["min_provisioned_read_capacity"]

  # The minimum number of units that should be provisioned with write capacity in the Auto Scaling group.
  # min_provisioned_write_capacity = ["min_provisioned_write_capacity"]

  # The maximum number of units that should be provisioned with read capacity in the Auto Scaling group.
  # max_provisioned_read_capcity = ["max_provisioned_read_capcity"]

  # The maximum number of units that should be provisioned with write capacity in the Auto Scaling group.
  # max_provisioned_write_capacity = ["max_provisioned_write_capacity"]

  # The target utilization percentage for read capacity. Target utilization is expressed in terms of the ratio of consumed capacity to provisioned capacity.
  # target_read_utilization = ["target_read_utilization"]

  # The target utilization percentage for write capacity. Target utilization is expressed in terms of the ratio of consumed capacity to provisioned capacity.
  # target_write_utilization = ["target_write_utilization"]

}

resource "aws_config_config_rule" "DYNAMODB_TABLE_ENCRYPTION_ENABLED" {
  depends_on = ["aws_config_configuration_recorder.cc_config_recorder"]

  description = "Checks whether the Amazon DynamoDB tables are encrypted and checks their status. The rule is COMPLIANT if the status is enabled or enabling."

  name            = "DYNAMODB_TABLE_ENCRYPTION_ENABLED"
  source {
    owner             = "AWS"
    source_identifier = "DYNAMODB_TABLE_ENCRYPTION_ENABLED"
  }


}

resource "aws_config_config_rule" "DYNAMODB_THROUGHPUT_LIMIT_CHECK" {
  depends_on = ["aws_config_configuration_recorder.cc_config_recorder"]

  description = "Checks whether provisioned DynamoDB throughput is approaching the maximum limit for your account. By default, the rule checks if provisioned throughput exceeds a threshold of 80% of your account limits."

  name            = "DYNAMODB_THROUGHPUT_LIMIT_CHECK"
  source {
    owner             = "AWS"
    source_identifier = "DYNAMODB_THROUGHPUT_LIMIT_CHECK"
  }


  # Percentage of provisioned read capacity units for your account. When this value is reached, the rule is marked as NON_COMPLIANT.
  # account_rcu_threshold_percentage = ["account_rcu_threshold_percentage"]

  # Percentage of provisioned write capacity units for your account. When this value is reached, the rule is marked as NON_COMPLIANT.
  # account_wcu_threshold_percentage = ["account_wcu_threshold_percentage"]

}

resource "aws_config_config_rule" "RDS_ENHANCED_MONITORING_ENABLED" {
  depends_on = ["aws_config_configuration_recorder.cc_config_recorder"]

  description = "Checks whether enhanced monitoring is enabled for Amazon Relational Database Service (Amazon RDS) instances."

  name            = "RDS_ENHANCED_MONITORING_ENABLED"
  source {
    owner             = "AWS"
    source_identifier = "RDS_ENHANCED_MONITORING_ENABLED"
  }


  # (Optional) An integer value in seconds between points when enhanced monitoring metrics are collected for the database instance. The valid values are 1, 5, 10, 15, 30, and 60.
  # monitoring_interval = ["monitoring_interval"]



}

resource "aws_config_config_rule" "RDS_INSTANCE_PUBLIC_ACCESS_CHECK" {
  depends_on = ["aws_config_configuration_recorder.cc_config_recorder"]

  description = "Check whether the Amazon Relational Database Service instances are not publicly accessible. The rule is NON_COMPLIANT if the publiclyAccessible field is true in the instance configuration item."

  name            = "RDS_INSTANCE_PUBLIC_ACCESS_CHECK"
  source {
    owner             = "AWS"
    source_identifier = "RDS_INSTANCE_PUBLIC_ACCESS_CHECK"
  }


}

resource "aws_config_config_rule" "RDS_MULTI_AZ_SUPPORT" {
  depends_on = ["aws_config_configuration_recorder.cc_config_recorder"]

  description = "Checks whether high availability is enabled for your RDS DB instances."

  name            = "RDS_MULTI_AZ_SUPPORT"
  source {
    owner             = "AWS"
    source_identifier = "RDS_MULTI_AZ_SUPPORT"
  }


}

resource "aws_config_config_rule" "RDS_SNAPSHOTS_PUBLIC_PROHIBITED" {
  depends_on = ["aws_config_configuration_recorder.cc_config_recorder"]

  description = "Checks if Amazon Relational Database Service (Amazon RDS) snapshots are public. The rule is NON_COMPLIANT if any existing and new Amazon RDS snapshots are public."

  name            = "RDS_SNAPSHOTS_PUBLIC_PROHIBITED"
  source {
    owner             = "AWS"
    source_identifier = "RDS_SNAPSHOTS_PUBLIC_PROHIBITED"
  }


}

resource "aws_config_config_rule" "RDS_STORAGE_ENCRYPTED" {
  depends_on = ["aws_config_configuration_recorder.cc_config_recorder"]

  description = "Checks whether storage encryption is enabled for your RDS DB instances."

  name            = "RDS_STORAGE_ENCRYPTED"
  source {
    owner             = "AWS"
    source_identifier = "RDS_STORAGE_ENCRYPTED"
  }


  # KMS key ID or ARN used to encrypt the storage.
  # kms_key_id = ["kms_key_id"]

}

resource "aws_config_config_rule" "REDSHIFT_CLUSTER_CONFIGURATION_CHECK" {
  depends_on = ["aws_config_configuration_recorder.cc_config_recorder"]

  description = "Checks whether Amazon Redshift clusters have the specified settings."

  name            = "REDSHIFT_CLUSTER_CONFIGURATION_CHECK"
  source {
    owner             = "AWS"
    source_identifier = "REDSHIFT_CLUSTER_CONFIGURATION_CHECK"
  }


  # Database encryption is enabled
  # cluster_db_encrpyted = ["cluster_db_encrypted"]

  # Specific node type
  # node_types = ["node_types"]

  # Audit logging is enabled 
  # logging_enabled = ["logging_enabled"]

}

resource "aws_config_config_rule" "REDSHIFT_CLUSTER_MAINTENANCESETTINGS_CHECK" {
  depends_on = ["aws_config_configuration_recorder.cc_config_recorder"]

  description = "Checks whether Amazon Redshift clusters have the specified maintenance settings."

  name            = "REDSHIFT_CLUSTER_MAINTENANCESETTINGS_CHECK"
  source {
    owner             = "AWS"
    source_identifier = "REDSHIFT_CLUSTER_MAINTENANCESETTINGS_CHECK"
  }


  # Allow version upgrade is enabled
  # allow_version_upgrade = ["allow_version_upgrade"]

  # Scheduled maintenance window for clusters (for example, Mon:09:30-Mon:10:00).
  # Preferred_maintenance_window = ["preferred_maintenance_window"]

  # Number of days to retain automated snapshots.
  # automated_snapshot_retention_period = ["automated_snapshot_retention_period"]

}

resource "aws_config_config_rule" "REDSHIFT_CLUSTER_PUBLIC_ACCESS_CHECK" {
  depends_on = ["aws_config_configuration_recorder.cc_config_recorder"]

  description = "Checks whether Amazon Redshift clusters are not publicly accessible. The rule is NON_COMPLIANT if the publiclyAccessible field is true in the cluster configuration item."

  name            = "REDSHIFT_CLUSTER_PUBLIC_ACCESS_CHECK"
  source {
    owner             = "AWS"
    source_identifier = "REDSHIFT_CLUSTER_PUBLIC_ACCESS_CHECK"
  }


}

# Machine Learning 

resource "aws_config_config_rule" "SAGEMAKER_ENDPOINT_CONFIGURATION_KMS_KEY_CONFIGURED" {
  depends_on = ["aws_config_configuration_recorder.cc_config_recorder"]

  description = "Checks whether AWS Key Management Service (KMS) key is configured for an Amazon SageMaker endpoint configuration. The rule is NON_COMPLIANT if KmsKeyId is not specified for the Amazon SageMaker endpoint configuration."

  name            = "SAGEMAKER_ENDPOINT_CONFIGURATION_KMS_KEY_CONFIGURED"
  source {
    owner             = "AWS"
    source_identifier = "SAGEMAKER_ENDPOINT_CONFIGURATION_KMS_KEY_CONFIGURED"
  }


  # (Optional) Comma-separated list of specific AWS KMS key ARNs allowed for an Amazon SageMaker endpoint configuration.
  # kms_key_arns = ["kms_key_arns"]

}

resource "aws_config_config_rule" "SAGEMAKER_NOTEBOOK_NO_DIRECT_INTERNET_ACCESS" {
  depends_on = ["aws_config_configuration_recorder.cc_config_recorder"]

  description = "Checks whether direct internet access is disabled for an Amazon SageMaker notebook instance. The rule is NON_COMPLIANT if Amazon SageMaker notebook instances are internet-enabled."

  name            = "SAGEMAKER_NOTEBOOK_NO_DIRECT_INTERNET_ACCESS"
  source {
    owner             = "AWS"
    source_identifier = "SAGEMAKER_NOTEBOOK_NO_DIRECT_INTERNET_ACCESS"
  }


}

resource "aws_config_config_rule" "SAGEMAKER_NOTEBOOK_INSTANCE_KMS_KEY_CONFIGURED" {
  depends_on = ["aws_config_configuration_recorder.cc_config_recorder"]

  description = "Check whether an AWS Key Management Service (KMS) key is configured for Amazon SageMaker notebook instance. The rule is not NON_COMPLIANT if kmsKeyId is not specified for the Amazon SageMaker notebook instance."

  name            = "SAGEMAKER_NOTEBOOK_INSTANCE_KMS_KEY_CONFIGURED"
  source {
    owner             = "AWS"
    source_identifier = "SAGEMAKER_NOTEBOOK_INSTANCE_KMS_KEY_CONFIGURED"
  }


  # Comma-separated list of allowed AWS KMS key IDs allowed for Amazon SageMaker notebook instance.
  # kms_arms = ["kms_arms"]

}

# Managment and Governance

resource "aws_config_config_rule" "CLOUDFORMATION_STACK_DRIFT_DETECTION_CHECK" {
  depends_on = ["aws_config_configuration_recorder.cc_config_recorder"]

  description = "Checks whether an AWS CloudFormation stack's actual configuration differs, or has drifted, from it's expected configuration. A stack is considered to have drifted if one or more of its resources differ from their expected configuration. The rule and the stack are COMPLIANT when the stack drift status is IN_SYNC. The rule and the stack are NON_COMPLIANT when the stack drift status is DRIFTED."

  name            = "CLOUDFORMATION_STACK_DRIFT_DETECTION_CHECK"
  source {
    owner             = "AWS"
    source_identifier = "CLOUDFORMATION_STACK_DRIFT_DETECTION_CHECK"
  }


  # The AWS CloudFormation role ARN with IAM policy permissions to detect drift for AWS CloudFormation stacks.
  # cloudformation_role_arn = ["cloudformation_role_arn"]

}

resource "aws_config_config_rule" "CLOUDFORMATION_STACK_NOTIFICATION_CHECK" {
  depends_on = ["aws_config_configuration_recorder.cc_config_recorder"]

  description = "Checks whether your CloudFormation stacks are sending event notifications to an SNS topic. Optionally checks whether specified SNS topics are used."

  name            = "CLOUDFORMATION_STACK_NOTIFICATION_CHECK"
  source {
    owner             = "AWS"
    source_identifier = "CLOUDFORMATION_STACK_NOTIFICATION_CHECK"
  }


  # SNS Topoc ARN
  # sns_topic_1 = ["sns_topic_1"]

  # SNS Topoc ARN
  # sns_topic_2 = ["sns_topic_2"]

  # SNS Topoc ARN
  # sns_topic_3 = ["sns_topic_3"]

  # SNS Topoc ARN
  # sns_topic_4 = ["sns_topic_4"]

  # SNS Topoc ARN
  # sns_topic_5 = ["sns_topic_5"]

  # continue this fomrat for as many SNS Topics that need stack notification check

}

resource "aws_config_config_rule" "CLOUD_TRAIL_CLOUD_WATCH_LOGS_ENABLED" {
  depends_on = ["aws_config_configuration_recorder.cc_config_recorder"]

  description = "Checks whether AWS CloudTrail trails are configured to send logs to Amazon CloudWatch Logs. The trail is NON_COMPLIANT if the CloudWatchLogsLogGroupArn property of the trail is empty."

  name            = "CLOUD_TRAIL_CLOUD_WATCH_LOGS_ENABLED"
  source {
    owner             = "AWS"
    source_identifier = "CLOUD_TRAIL_CLOUD_WATCH_LOGS_ENABLED"
  }


}

resource "aws_config_config_rule" "CLOUD_TRAIL_ENABLED" {
  depends_on = ["aws_config_configuration_recorder.cc_config_recorder"]

  description = "Checks whether AWS CloudTrail is enabled in your AWS account. Optionally, you can specify which S3 bucket, SNS topic, and Amazon CloudWatch Logs ARN to use."

  name            = "CLOUD_TRAIL_ENABLED"
  source {
    owner             = "AWS"
    source_identifier = "CLOUD_TRAIL_ENABLED"
  }


  # The name of the S3 bucket for AWS CloudTrail to deliver log files to.
  # s3_bucket_name = ["s3_bucket_name"]

  # The ARN of the SNS topic for AWS CloudTrail to use for notifications.
  # sns_topic_arn = ["sns_topic_arn"]

  # The ARN of the Amazon CloudWatch log group for AWS CloudTrail to send data to.
  # cloud_watch_logs_log_group_arn = ["cloud_watch_logs_log_group_arn"]

}

resource "aws_config_config_rule" "CLOUD_TRAIL_ENCRYPTION_ENABLED" {
  depends_on = ["aws_config_configuration_recorder.cc_config_recorder"]

  description = "Checks whether AWS CloudTrail is configured to use the server side encryption (SSE) AWS Key Management Service (AWS KMS) customer master key (CMK) encryption. The rule is COMPLIANT if the KmsKeyId is defined."

  name            = "CLOUD_TRAIL_ENCRYPTION_ENABLED"
  source {
    owner             = "AWS"
    source_identifier = "CLOUD_TRAIL_ENCRYPTION_ENABLED"
  }


}

resource "aws_config_config_rule" "CLOUD_TRAIL_LOG_FILE_VALIDATION_ENABLED" {
  depends_on = ["aws_config_configuration_recorder.cc_config_recorder"]

  description = "Checks whether AWS CloudTrail creates a signed digest file with logs. AWS recommends that the file validation must be enabled on all trails. The rule is NON_COMPLIANT if the validation is not enabled."

  name            = "CLOUD_TRAIL_LOG_FILE_VALIDATION_ENABLED"
  source {
    owner             = "AWS"
    source_identifier = "CLOUD_TRAIL_LOG_FILE_VALIDATION_ENABLED"
  }


}

resource "aws_config_config_rule" "CLOUDTRAIL_S3_DATAEVENTS_ENABLED" {
  depends_on = ["aws_config_configuration_recorder.cc_config_recorder"]

  description = "Checks whether at least one AWS CloudTrail trail is logging Amazon S3 data events for all S3 buckets. The rule is NON_COMPLIANT if trails that log data events for S3 buckets are not configured."

  name            = "CLOUDTRAIL_S3_DATAEVENTS_ENABLED"
  source {
    owner             = "AWS"
    source_identifier = "CLOUDTRAIL_S3_DATAEVENTS_ENABLED"
  }


  # (Optional) Comma-separated list of S3 bucket names for which data events logging should be enabled. Default behavior checks for all S3 buckets.
  # s3_bucket_names = ["s3bucket_names"]

}

resource "aws_config_config_rule" "CLOUDWATCH_ALARM_ACTION_CHECK" {
  depends_on = ["aws_config_configuration_recorder.cc_config_recorder"]

  description = "Checks whether CloudWatch alarms have at least one alarm action, one INSUFFICIENT_DATA action, or one OK action enabled. Optionally, checks whether any of the actions matches one of the specified ARNs."

  name            = "CLOUDWATCH_ALARM_ACTION_CHECK"
  source {
    owner             = "AWS"
    source_identifier = "CLOUDWATCH_ALARM_ACTION_CHECK"
  }


  # Alarms have at least one action.
  # The default value is true.
  # alarm_action_required = ["alarm_action_required"]

  # Alarms have at least one action when the alarm transitions to the INSUFFICIENT_DATA state from any other state.
  # The default value is true.
  # insufficient_data_action_required = ["insufficient_data_action_required"]

  # Alarms have at least one action when the alarm transitions to an OK state from any other state.
  # The default value is false.
  # ok_action_required = ["ok_action_required"]

  # The action to execute, specified as an ARN.
  # action_1 = ["action_1"]

  # The action to execute, specified as an ARN.
  # action_2 = ["action_2"]

  # The action to execute, specified as an ARN.
  # action_3 = ["action_3"]

  # The action to execute, specified as an ARN.
  # action_4 = ["action_4"]

  # The action to execute, specified as an ARN.
  # action_5 = ["action_5"]

  # Continue this format for as many actions you need to execute 


}

resource "aws_config_config_rule" "CLOUDWATCH_ALARM_RESOURCE_CHECK" {
  depends_on = ["aws_config_configuration_recorder.cc_config_recorder"]

  description = "Checks whether the specified resource type has a CloudWatch alarm for the specified metric. For resource type, you can specify EBS volumes, EC2 instances, RDS clusters, or S3 buckets."

  name            = "CLOUDWATCH_ALARM_RESOURCE_CHECK"
  source {
    owner             = "AWS"
    source_identifier = "CLOUDWATCH_ALARM_RESOURCE_CHECK"
  }


  # AWS resource type. The value can be one of the following:
  # AWS::EC2::Volume
  # AWS::EC2::Instance
  # AWS::S3::Bucket
  # resource_type = ["resource_type"]

  # The name of the metric associated with the alarm (for example, "CPUUtilization" for EC2 instances).
  # metric_name = ["metric_name"]


}

resource "aws_config_config_rule" "CLOUDWATCH_ALARM_SETTINGS_CHECK" {
  depends_on = ["aws_config_configuration_recorder.cc_config_recorder"]

  description = "Checks whether CloudWatch alarms with the given metric name have the specified settings."

  name            = "CLOUDWATCH_ALARM_SETTINGS_CHECK"
  source {
    owner             = "AWS"
    source_identifier = "CLOUDWATCH_ALARM_SETTINGS_CHECK"
  }


  # The name for the metric associated with the alarm.
  # metric_name = ["metric_name"]

  # The value against which the specified statistic is compared.
  # threshold = ["threshold"]

  # The number of periods in which data is compared to the specified threshold.
  # evaluation_period = ["evaluation_period"]

  # The period, in seconds, during which the specified statistic is applied. The default value is 300 seconds.
  # period = ["period"]

  # The operation for comparing the specified statistic and threshold (for example, "GreaterThanThreshold").
  # comparison_operator = ["comparison_operator"]

  # The statistic for the metric associated with the alarm (for example, "Average" or "Sum").
  # statistic = ["statistic"]


}

resource "aws_config_config_rule" "CLOUDWATCH_LOG_GROUP_ENCRYPTED" {
  depends_on = ["aws_config_configuration_recorder.cc_config_recorder"]

  description = "Checks whether a log group in Amazon CloudWatch Logs is encrypted. The rule is NON_COMPLIANT if CloudWatch Logs has a log group without encryption enabled."

  name            = "CLOUDWATCH_LOG_GROUP_ENCRYPTED"
  source {
    owner             = "AWS"
    source_identifier = "CLOUDWATCH_LOG_GROUP_ENCRYPTED"
  }


  # (Optional) Amazon Resource Name (ARN) of an AWS Key Management Service (KMS) key that is used to encrypt the CloudWatch Logs log group.
  # kms_key_id = ["kms_key_id"]
}

resource "aws_config_config_rule" "CODEBUILD_PROJECT_ENVVAR_AWSCRED_CHECK" {
  depends_on = ["aws_config_configuration_recorder.cc_config_recorder"]

  description = "Checks whether the project contains environment variables AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY. The rule is NON_COMPLIANT when the project environment variables contains plaintext credentials."

  name            = "CODEBUILD_PROJECT_ENVVAR_AWSCRED_CHECK"
  source {
    owner             = "AWS"
    source_identifier = "CODEBUILD_PROJECT_ENVVAR_AWSCRED_CHECK"
  }


}

resource "aws_config_config_rule" "CODEBUILD_PROJECT_SOURCE_REPO_URL_CHECK" {
  depends_on = ["aws_config_configuration_recorder.cc_config_recorder"]

  description = "Checks whether the GitHub or Bitbucket source repository URL contains either personal access tokens or user name and password. The rule is COMPLIANT with the usage of OAuth to grant authorization for accessing GitHub or Bitbucket repositories."

  name            = "CODEBUILD_PROJECT_SOURCE_REPO_URL_CHECK"
  source {
    owner             = "AWS"
    source_identifier = "CODEBUILD_PROJECT_SOURCE_REPO_URL_CHECK"
  }


}

resource "aws_config_config_rule" "CODEPIPELINE_DEPLOYMENT_COUNT_CHECK" {
  depends_on = ["aws_config_configuration_recorder.cc_config_recorder"]

  description = "Checks whether the first deployment stage of the AWS CodePipeline performs more than one deployment. Optionally, checks if each of the subsequent remaining stages deploy to more than the specified number of deployments (deploymentLimit). The rule is NON_COMPLIANT if the first stage in the AWS CodePipeline deploys to more than one region and the AWS CodePipeline deploys to more than the number specified in the deploymentLimit."

  name            = "CODEPIPELINE_DEPLOYMENT_COUNT_CHECK"
  source {
    owner             = "AWS"
    source_identifier = "CODEPIPELINE_DEPLOYMENT_COUNT_CHECK"
  }


  # The maximum number of deployments each stage can perform.
  # deployment_limit = ["deployment_limit"]

}

resource "aws_config_config_rule" "CODEPIPELINE_REGION_FANOUT_CHECK" {
  depends_on = ["aws_config_configuration_recorder.cc_config_recorder"]

  description = "Checks whether each stage in the AWS CodePipeline deploys to more than N times the number of the regions the AWS CodePipeline has deployed in all the previous combined stages, where N is the region fanout number. The first deployment stage can deploy to a maximum of one region and the second deployment stage can deploy to a maximum number specified in the regionFanoutFactor. If you do not provide a regionFanoutFactor, by default the value is three. For example: If 1st deployment stage deploys to one region and 2nd deployment stage deploys to three regions, 3rd deployment stage can deploy to 12 regions, that is, sum of previous stages multiplied by the region fanout (three) number. The rule is NON_COMPLIANT if the deployment is in more than one region in 1st stage or three regions in 2nd stage or 12 regions in 3rd stage."

  name            = "CODEPIPELINE_REGION_FANOUT_CHECK"
  source {
    owner             = "AWS"
    source_identifier = "CODEPIPELINE_REGION_FANOUT_CHECK"
  }


  # The number of regions the AWS CodePipeline has deployed to in all previous stages is the acceptable number of regions any stage can deploy to
  # region_fanout_factor = ["region_fanout_factor"]

}

resource "aws_config_config_rule" "MULTI_REGION_CLOUD_TRAIL_ENABLED" {
  depends_on = ["aws_config_configuration_recorder.cc_config_recorder"]

  description = "Checks that there is at least one multi-region AWS CloudTrail. The rule is NON_COMPLIANT if the trails do not match inputs parameters."

  name            = "MULTI_REGION_CLOUD_TRAIL_ENABLED"
  source {
    owner             = "AWS"
    source_identifier = "MULTI_REGION_CLOUD_TRAIL_ENABLED"
  }


  # the following parameters are all optional 

  # Name of Amazon S3 bucket for AWS CloudTrail to deliver log files to. 
  # s3_bucket_name = ["s3_bucket_name"]

  # Amazon SNS topic ARN for AWS CloudTrail to use for notifications.
  # sns_topic_arn = ["sns_topic_arn"]

  # Amazon CloudWatch log group ARN for AWS CloudTrail to send data to.
  # cloud_watch_logs_log_group_arn = ["cloud_Watch_logs_log_group_arn"]

  # Event selector to include management events for the AWS CloudTrail.
  # include_management_events = ["include_managment_events"]

  # Type of events to record. Valid values are ReadOnly, WriteOnly and ALL.
  # read_write_type = ["read_write_type"]


}

resource "aws_config_config_rule" "REQUIRED_TAGS" {
  depends_on = ["aws_config_configuration_recorder.cc_config_recorder"]

  description = "Checks whether your resources have the tags that you specify. For example, you can check whether your EC2 instances have the 'CostCenter' tag. Separate multiple values with commas."

  name            = "REQUIRED_TAGS"
  source {
    owner             = "AWS"
    source_identifier = "REQUIRED_TAGS"
  }


  # Key of the required tag.
  # tag_1_key = ["tag_1_key"]

  # Optional value of the required tag. Separate multiple values with commas.
  # tag_1_value = ["tag_1_value"]

  # continue this format for as many required keys you have


}

# Migration and Transfer 

resource "aws_config_config_rule" "DMS_REPLICATION_NOT_PUBLIC" {
  depends_on = ["aws_config_configuration_recorder.cc_config_recorder"]

  description = "Checks whether AWS Database Migration Service replication instances are public. The rule is NON_COMPLIANT if PubliclyAccessible field is true."

  name            = "DMS_REPLICATION_NOT_PUBLIC"
  source {
    owner             = "AWS"
    source_identifier = "DMS_REPLICATION_NOT_PUBLIC"
  }


}

# Network and Content Delivery 

resource "aws_config_config_rule" "ALB_HTTP_TO_HTTPS_REDIRECTION_CHECK" {
  depends_on = ["aws_config_configuration_recorder.cc_config_recorder"]

  description = "Checks whether HTTP to HTTPS redirection is configured on all HTTP listeners of Application Load Balancers. The rule is NON_COMPLIANT if one or more HTTP listeners of Application Load Balancers do not have HTTP to HTTPS redirection configured."

  name            = "ALB_HTTP_TO_HTTPS_REDIRECTION_CHECK"
  source {
    owner             = "AWS"
    source_identifier = "ALB_HTTP_TO_HTTPS_REDIRECTION_CHECK"
  }


}

resource "aws_config_config_rule" "API_GW_EXECUTION_LOGGING_ENABLED" {
  depends_on = ["aws_config_configuration_recorder.cc_config_recorder"]

  description = "Checks that all methods in Amazon API Gateway stage has logging enabled. The rule is NON_COMPLIANT if logging is not enabled. The rule is NON_COMPLIANT if loggingLevel is neither ERROR nor INFO."

  name            = "API_GW_EXECUTION_LOGGING_ENABLED"
  source {
    owner             = "AWS"
    source_identifier = "API_GW_EXECUTION_LOGGING_ENABLED"
  }


  # (Optional) Comma-separated list of specific logging levels (for example, ERROR, INFO or ERROR,INFO).
  # logging_level = ["logging_level"]

}

resource "aws_config_config_rule" "API_GW_CACHE_ENABLED_AND_ENCRYPTED" {
  depends_on = ["aws_config_configuration_recorder.cc_config_recorder"]

  description = "Checks that all methods in Amazon API Gateway stages have caching enabled and encrypted. The rule is NON_COMPLIANT if any method in an API Gateway stage is not configured for caching or the cache is not encrypted."

  name            = "API_GW_CACHE_ENABLED_AND_ENCRYPTED"
  source {
    owner             = "AWS"
    source_identifier = "API_GW_CACHE_ENABLED_AND_ENCRYPTED"
  }


}

resource "aws_config_config_rule" "API_GW_ENDPOINT_TYPE_CHECK" {
  depends_on = ["aws_config_configuration_recorder.cc_config_recorder"]

  description = "Checks that Amazon API Gateway APIs are of the type specified in the rule parameter endpointConfigurationType. The rule returns NON_COMPLIANT if the REST API does not match the endpoint type configured in the rule parameter."

  name            = "API_GW_ENDPOINT_TYPE_CHECK"
  source {
    owner             = "AWS"
    source_identifier = "API_GW_ENDPOINT_TYPE_CHECK"
  }


  # (Required) Comma-separated list of allowed endpoint types. Allowed values are REGIONAL, PRIVATE and EDGE.
  # endpoint_configuration_type = ["endpoint_configuration_type"]

}

resource "aws_config_config_rule" "CLOUDFRONT_VIEWER_POLICY_HTTPS" {
  depends_on = ["aws_config_configuration_recorder.cc_config_recorder"]

  description = "Checks whether your Amazon CloudFront distributions use HTTPS (directly or via a redirection). The rule is NON_COMPLIANT if the value of ViewerProtocolPolicy is set to allow-all for defaultCacheBehavior or for cacheBehaviors. This means that the rule is non compliant when viewers can use HTTP or HTTPS."

  name            = "CLOUDFRONT_VIEWER_POLICY_HTTPS"
  source {
    owner             = "AWS"
    source_identifier = "CLOUDFRONT_VIEWER_POLICY_HTTPS"
  }


}

resource "aws_config_config_rule" "INTERNET_GATEWAY_AUTHORIZED_VPC_ONLY" {
  depends_on = ["aws_config_configuration_recorder.cc_config_recorder"]

  description = "Checks that Internet gateways (IGWs) are only attached to an authorized Amazon Virtual Private Cloud (VPCs). The rule is NON_COMPLIANT if IGWs are not attached to an authorized VPC."

  name            = "INTERNET_GATEWAY_AUTHORIZED_VPC_ONLY"
  source {
    owner             = "AWS"
    source_identifier = "INTERNET_GATEWAY_AUTHORIZED_VPC_ONLY"
  }


  # Comma-separated list of the authorized VPC IDs with attached IGWs. If parameter is not provided all attached IGWs will be NON_COMPLIANT.
  # authorized_vpc_ids = ["authorized_vpc_ids"]

}

resource "aws_config_config_rule" "SERVICE_VPC_ENDPOINT_ENABLED" {
  depends_on = ["aws_config_configuration_recorder.cc_config_recorder"]

  description = "Checks whether Service Endpoint for the service provided in rule parameter is created for each Amazon VPC. The rule returns NON_COMPLIANT if an Amazon VPC doesn't have a VPC endpoint created for the service."

  name            = "SERVICE_VPC_ENDPOINT_ENABLED"
  source {
    owner             = "AWS"
    source_identifier = "SERVICE_VPC_ENDPOINT_ENABLED"
  }


  # (Optional) The short name or suffix for the service. To get a list of available service names or valid suffix list, use DescribeVpcEndpointServices.
  # service_name = ["service_name"]


}

resource "aws_config_config_rule" "VPC_DEFAULT_SECURITY_GROUP_CLOSED" {
  depends_on = ["aws_config_configuration_recorder.cc_config_recorder"]

  description = "Checks that the default security group of any Amazon Virtual Private Cloud (VPC) does not allow inbound or outbound traffic. The rule returns NOT_APPLICABLE if the security group is not default. The rule is NON_COMPLIANT if the default security group has one or more inbound or outbound traffic."

  name            = "VPC_DEFAULT_SECURITY_GROUP_CLOSED"
  source {
    owner             = "AWS"
    source_identifier = "VPC_DEFAULT_SECURITY_GROUP_CLOSED"
  }


}

resource "aws_config_config_rule" "VPC_FLOW_LOGS_ENABLED" {
  depends_on = ["aws_config_configuration_recorder.cc_config_recorder"]

  description = "Checks whether Amazon Virtual Private Cloud flow logs are found and enabled for Amazon VPC."

  name            = "VPC_FLOW_LOGS_ENABLED"
  source {
    owner             = "AWS"
    source_identifier = "VPC_FLOW_LOGS_ENABLED"
  }


  # The valid trafficType values are ACCEPT, REJECT, or ALL.
  # traffic_type = ["traffic_type"]


}

resource "aws_config_config_rule" "VPC_SG_OPEN_ONLY_TO_AUTHORIZED_PORTS" {
  depends_on = ["aws_config_configuration_recorder.cc_config_recorder"]

  description = "Checks whether the security group with 0.0.0.0/0 of any Amazon Virtual Private Cloud (Amazon VPC) allows only specific inbound TCP or UDP traffic. The rule and any security group with inbound 0.0.0.0/0. are NON_COMPLIANT if you do not provide any ports in the parameters."

  name            = "VPC_SG_OPEN_ONLY_TO_AUTHORIZED_PORTS"
  source {
    owner             = "AWS"
    source_identifier = "VPC_SG_OPEN_ONLY_TO_AUTHORIZED_PORTS"
  }


  # (optional) Comma-separated list of TCP ports authorized to be open to 0.0.0.0/0. Ranges are defined by a dash; for example, "443,1020-1025".
  # authorized_tcp_ports = ["authorized_tcp_ports"]

  # (optional) Comma-separated list of UDP ports authorized to be open to 0.0.0.0/0. Ranges are defined by a dash; for example, "500,1020-1025".
  # authorized_udp_ports = ["authorized_udp_ports"]
}

resource "aws_config_config_rule" "VPC_VPN_2_TUNNELS_UP" {
  depends_on = ["aws_config_configuration_recorder.cc_config_recorder"]

  description = "Checks that both AWS Virtual Private Network tunnels provided by AWS Site-to-Site VPN are in UP status. The rule returns NON_COMPLIANT if one or both tunnels are in DOWN status."

  name            = "VPC_VPN_2_TUNNELS_UP"
  source {
    owner             = "AWS"
    source_identifier = "VPC_VPN_2_TUNNELS_UP"
  }


}

# Security Identity & Compliance

resource "aws_config_config_rule" "ACCESS_KEYS_ROTATED" {
  depends_on = ["aws_config_configuration_recorder.cc_config_recorder"]

  description = "Checks whether the active access keys are rotated within the number of days specified in maxAccessKeyAge. The rule is NON_COMPLIANT if the access keys have not been rotated for more than maxAccessKeyAge number of days."

  name            = "ACCESS_KEYS_ROTATED"
  source {
    owner             = "AWS"
    source_identifier = "ACCESS_KEYS_ROTATED"
  }


  # Maximum number of days within which the access keys must be rotated. The default value is 90 days.
  # max_access_key_age = ["max_access_key_age"]

}

resource "aws_config_config_rule" "ACM_CERTIFICATE_EXPIRATION_CHECK" {
  depends_on = ["aws_config_configuration_recorder.cc_config_recorder"]

  description = "Checks whether ACM Certificates in your account are marked for expiration within the specified number of days. Certificates provided by ACM are automatically renewed. ACM does not automatically renew certificates that you import."

  name            = "ACM_CERTIFICATE_EXPIRATION_CHECK"
  source {
    owner             = "AWS"
    source_identifier = "ACM_CERTIFICATE_EXPIRATION_CHECK"
  }


  # Specify the number of days before the rule flags the ACM Certificate as NON_COMPLIANT.
  # days_to_expiration = ["days_to_expiration"]

}

resource "aws_config_config_rule" "CMK_BACKING_KEY_ROTATION_ENABLED" {
  depends_on = ["aws_config_configuration_recorder.cc_config_recorder"]

  description = "Checks that key rotation is enabled for each customer master key (CMK). The rule is COMPLIANT, if the key rotation is enabled for specific key object. The rule is not applicable to CMKs that have imported key material."

  name            = "CMK_BACKING_KEY_ROTATION_ENABLED"
  source {
    owner             = "AWS"
    source_identifier = "CMK_BACKING_KEY_ROTATION_ENABLED"
  }




}

resource "aws_config_config_rule" "FMS_SECURITY_GROUP_AUDIT_POLICY_CHECK" {
  depends_on = ["aws_config_configuration_recorder.cc_config_recorder"]

  description = "Checks whether the security groups associated inScope resources are compliant with the master security groups at each rule level based on allowSecurityGroup and denySecurityGroup flag."

  name            = "FMS_SECURITY_GROUP_AUDIT_POLICY_CHECK"
  source {
    owner             = "AWS"
    source_identifier = "FMS_SECURITY_GROUP_AUDIT_POLICY_CHECK"
  }


  # (mandatory) Comma-separated list of master security groups IDs. The rule will check if security groups associated inScope resources are compliant with the master security groups at each rule level.
  # master_security_group_ids = ["master_security_group_ids"]

  # (mandatory) The resource tags associated with the rule (for example, { "tagKey1" : ["tagValue1"], "tagKey2" : ["tagValue2", "tagValue3"] }").
  # resource_tags = ["resource_tags"]

  # (mandatory) If true, the AWS Config rule owner is in Firewall Manager security group audit policy scope.
  # in_scope = ["in_scope"]

  # (mandatory) If true, exclude resources that match resourceTags.
  # exclude_resource_tags = ["exclude_resource_tags"]

  # (mandatory) The resource types such as Amazon EC2 instance or elastic network interface or security group supported by this rule.
  # resource_types = ["resource_types"]

  # (mandatory) If true, AWS Firewall Manager will update NON_COMPLIANT resources according to FMS policy. AWS Config ignores this parameter when you create this rule.
  # fms_remediation_enabled = ["fms_remediation_enabled"]

  # (mandatory) If true, the rule will check to ensure that all inScope security groups are within the reference security group's inbound/outbound rules.
  # allow_security_group = ["allow_security_group"]

}

resource "aws_config_config_rule" "FMS_SECURITY_GROUP_CONTENT_CHECK" {
  depends_on = ["aws_config_configuration_recorder.cc_config_recorder"]

  description = "Checks whether AWS Firewall Manager created security groups content is the same as the master security groups. The rule is NON_COMPLIANT if the content does not match."

  name            = "FMS_SECURITY_GROUP_CONTENT_CHECK"
  source {
    owner             = "AWS"
    source_identifier = "FMS_SECURITY_GROUP_CONTENT_CHECK"
  }


  # (mandatory) Comma-separated list of VPC IDs in the account.
  # vpc_ids = ["vpc_ids"]

  # (mandatory) Comma-separated list of security groups IDs created by Firewall Manager in every Amazon VPC in an account. They are sorted by VPC IDs.
  # security_group_ids = ["security_group_ids"]

  # (mandatory) If true, AWS Firewall Manager will update NON_COMPLIANT resources according to FMS policy. AWS Config ignores this parameter when you create this rule.
  # fms_remediation_enabled = ["fms_remediation_enabled"]

  # (mandatory) If true, AWS Firewall Manager will check the security groups in the securityGroupsIds parameter.
  # revert_manual_security_group_changes_flag = ["revert_manual_security_group_changes_flag"]

  # (mandatory) If true, the rule will check to ensure that all inScope security groups are within the reference security group's inbound/outbound rules.
  # allow_security_group = ["allow_security_group"]

  # (mandatory) This parameter only applies to AWS Firewall Manager admin account. Comma-separated list of master security groups ID in Firewall Manager admin account.
  # master_securiy_group_ids = ["mandatory_security_group_ids"]

}

resource "aws_config_config_rule" "FMS_SECURITY_GROUP_RESOURCE_ASSOCIATION_CHECK" {
  depends_on = ["aws_config_configuration_recorder.cc_config_recorder"]

  description = "Checks whether Amazon EC2 or an elastic network interface is associated with AWS Firewall Manager security groups. The rule is NON_COMPLIANT if the resources are not associated with FMS security groups."

  name            = "FMS_SECURITY_GROUP_RESOURCE_ASSOCIATION_CHECK"
  source {
    owner             = "AWS"
    source_identifier = "FMS_SECURITY_GROUP_RESOURCE_ASSOCIATION_CHECK"
  }


  # (mandatory) Comma-separated list of VPC IDs in the account.
  # vpc_ids = ["vpc_ids"]

  # (mandatory) Comma-separated list of security groups IDs created by Firewall Manager in every Amazon VPC in an account. They are sorted by VPC IDs.
  # security_group_ids = ["security_group_ids"]

  # (mandatory) The resource tags such as Amazon EC2 instance or elastic network interface associated with the rule (for example, { "tagKey1" : ["tagValue1"], "tagKey2" : ["tagValue2", "tagValue3"] }").
  # resource_tags = ["resource_tags"]

  # (mandatory) If true, exclude resources that match resourceTags.
  # exclude_resource_tags = ["exclude_resource_tags"]

  # The resource types such as Amazon EC2 instance or elastic network interface or security group supported by this rule.
  # resource_types = ["resource_types"]

  # (mandatory) If true, AWS Firewall Manager will update NON_COMPLIANT resources according to FMS policy. AWS Config ignores this parameter when you create this rule.
  # fms_remediation_enabled = ["fms_remediation_enabled"]

  # (mandatory) If true, only allows AWS Firewall Manager created security groups associated with resource.
  # exclusive_resource_security_group_management_flag = ["exclusive_resource_security_group_management_flag"]


}

resource "aws_config_config_rule" "FMS_SHIELD_RESOURCE_POLICY_CHECK" {
  depends_on = ["aws_config_configuration_recorder.cc_config_recorder"]

  description = "Checks whether an Application Load Balancer, Amazon CloudFront distributions, Elastic Load Balancer or Elastic IP has AWS Shield protection. This rule also checks if they have web ACL associated for Application Load Balancer and Amazon CloudFront distributions."

  name            = "FMS_SHIELD_RESOURCE_POLICY_CHECK"
  source {
    owner             = "AWS"
    source_identifier = "FMS_SHIELD_RESOURCE_POLICY_CHECK"
  }


  # The WebACLId of the web ACL.
  # web_acl_id = ["web_acl_id"]

  # The resource tags associated with the rule (for example, { "tagKey1" : ["tagValue1"], "tagKey2" : ["tagValue2", "tagValue3"] }").
  # resource_tags = ["resource_tags"]

  # If true, exclude the resources that match the resourceTags. If false, include all the resources that match the resourceTags.
  # exclude_resource_tags = ["exclude_resource_tags"]

  # A token generated by AWS Firewall Manager when creating the rule in your account. AWS Config ignores this parameter when you create this rule.
  # fms_managed_token = ["fms_managed_token"]

  # If true, AWS Firewall Manager will update NON_COMPLIANT resources according to FMS policy. AWS Config ignores this parameter when you create this rule.
  # fms_remediation_enabled = ["fms_remediation_enabled"]

}

resource "aws_config_config_rule" "FMS_WEBACL_RULEGROUP_ASSOCIATION_CHECK" {
  depends_on = ["aws_config_configuration_recorder.cc_config_recorder"]

  description = "Checks that the rule groups associate with the web ACL at the correct priority. The correct priority is decided by the rank of the rule groups in the ruleGroups parameter. When AWS Firewall Manager creates this rule, it assigns the highest priority 0 followed by 1, 2, and so on. The FMS policy owner specifies the ruleGroups rank in the FMS policy and can optionally enable remediation."

  name            = "FMS_WEBACL_RULEGROUP_ASSOCIATION_CHECK"
  source {
    owner             = "AWS"
    source_identifier = "FMS_WEBACL_RULEGROUP_ASSOCIATION_CHECK"
  }


  # Comma-separated list of RuleGroupIds and WafOverrideAction pairs (for example, RuleGroupId-1:NONE, RuleGroupId-2:COUNT). For this example, RuleGroupId-1 receives the highest priority 0 and RuleGroupId-2 receives priority 1.
  # rule_groups = ["rule_groups"]

  # A token generated by AWS Firewall Manager when creating the rule in your account. AWS Config ignores this parameter when you create this rule.
  # fms_managed_token = ["fms_managed_token"]

  # If true, AWS Firewall Manager will update NON_COMPLIANT resources according to FMS policy. AWS Config ignores this parameter when you create this rule.
  # fms_remediation_enabled = ["fms_remediation_enabled"]

}

resource "aws_config_config_rule" "GUARDDUTY_NON_ARCHIVED_FINDINGS" {
  depends_on = ["aws_config_configuration_recorder.cc_config_recorder"]

  description = "Checks whether the Amazon GuardDuty has findings that are non archived. The rule is NON_COMPLIANT if Amazon GuardDuty has non archived low/medium/high severity findings older than the specified number in the daysLowSev/daysMediumSev/daysHighSev parameter."

  name            = "GUARDDUTY_NON_ARCHIVED_FINDINGS"
  source {
    owner             = "AWS"
    source_identifier = "GUARDDUTY_NON_ARCHIVED_FINDINGS"
  }


  # The number of days Amazon GuardDuty low severity findings are allowed to stay non archived. The default is 30 days.
  # days_low_sev = ["days_low_sev"]

  # The number of days the Amazon GuardDuty medium severity findings are allowed to stay non archived. The default is 7 days.
  # days_medium_sev = ["days_medium_sev"]

  # The number of days Amazon GuardDuty high severity findings are allowed to stay non archived. The default is 1 day.
  # days_high_sev = ["days_high_sev"]

}

resource "aws_config_config_rule" "GUARDDUTY_ENABLED_CENTRALIZED" {
  depends_on = ["aws_config_configuration_recorder.cc_config_recorder"]

  description = "Checks whether Amazon GuardDuty is enabled in your AWS account and region. If you provide an AWS account for centralization, the rule evaluates the Amazon GuardDuty results in the centralized account. The rule is COMPLIANT when Amazon GuardDuty is enabled."

  name            = "GUARDDUTY_ENABLED_CENTRALIZED"
  source {
    owner             = "AWS"
    source_identifier = "GUARDDUTY_ENABLED_CENTRALIZED"
  }


  # Specify 12-digit AWS Account for centralization of Amazon GuardDuty results.
  # central_monitoring_account = ["central_monitoring_account"]


}

resource "aws_config_config_rule" "IAM_GROUP_HAS_USERS_CHECK" {
  depends_on = ["aws_config_configuration_recorder.cc_config_recorder"]

  description = "Checks whether IAM groups have at least one IAM user."

  name            = "IAM_GROUP_HAS_USERS_CHECK"
  source {
    owner             = "AWS"
    source_identifier = "IAM_GROUP_HAS_USERS_CHECK"
  }


}

resource "aws_config_config_rule" "IAM_PASSWORD_POLICY" {
  depends_on = ["aws_config_configuration_recorder.cc_config_recorder"]

  description = "Checks whether the account password policy for IAM users meets the specified requirements."

  name            = "IAM_PASSWORD_POLICY"
  source {
    owner             = "AWS"
    source_identifier = "IAM_PASSWORD_POLICY"
  }


  # Require at least one uppercase character in password.
  # require_upper_case_characters = ["require_upper_case_characters"]

  # Require at least one lowercase character in password.
  # require_lowercase_characters = ["require_lower_case_characters"]

  # Require at least one symbol in password.
  # require_symbols = ["require_symbols"]

  # Require at least one number in password.
  # require_numbers = ["require_numbers"]

  # Password minimum length.
  # minimum_password_length = ["minimum_password_length"]

  # Number of passwords before allowing reuse.
  # password_reuse_prevention = ["password_reuse_prevention"]

  # Number of days before password expiration.
  # max_password_age = ["max_password_age"]

}

resource "aws_config_config_rule" "IAM_POLICY_BLACKLISTED_CHECK" {
  depends_on = ["aws_config_configuration_recorder.cc_config_recorder"]

  description = "Checks whether for each IAM resource, a policy ARN in the input parameter is attached to the IAM resource. The rule is NON_COMPLIANT if the policy ARN is attached to the IAM resource. AWS Config marks the resource as COMPLIANT if the IAM resource is part of the exceptionList parameter irrespective of the presence of the policy ARN."

  name            = "IAM_POLICY_BLACKLISTED_CHECK"
  source {
    owner             = "AWS"
    source_identifier = "IAM_POLICY_BLACKLISTED_CHECK"
  }


  # Comma-separated list of policy ARNs.
  #policy_arns = ["policy_arns"]

  # Comma-separated list IAM users, groups, or roles that are exempt from this rule. For example, users:[user1;user2], groups:[group1;group2], roles:[role1;role2;role3].
  # exception_list = ["exception_list"]

}

resource "aws_config_config_rule" "IAM_POLICY_IN_USE" {
  depends_on = ["aws_config_configuration_recorder.cc_config_recorder"]

  description = "Checks whether the IAM policy ARN is attached to an IAM user, or an IAM group with one or more IAM users, or an IAM role with one or more trusted entity."

  name            = "IAM_POLICY_IN_USE"
  source {
    owner             = "AWS"
    source_identifier = "IAM_POLICY_IN_USE"
  }


  # (mandatory) An IAM policy Amazon Resource Name (ARN) to be checked
  # policy_arn = ["policy_arn"]

  # (optional) Specify the policy to be attached as an IAM user, IAM group, or IAM role. Valid values are IAM_USER, IAM_GROUP, IAM_ROLE, or ANY. Default value is ANY.
  # policy_usage_type = ["policy_usage_type"]

}

resource "aws_config_config_rule" "IAM_POLICY_NO_STATEMENTS_WITH_ADMIN_ACCESS" {
  depends_on = ["aws_config_configuration_recorder.cc_config_recorder"]

  description = "This rule checks only the IAM policies that you create. It does not check IAM Managed Policies. When you enable the rule, this rule checks all of the customer managed policies in your account, and all new policies that you create."

  name            = "IAM_POLICY_NO_STATEMENTS_WITH_ADMIN_ACCESS"
  source {
    owner             = "AWS"
    source_identifier = "IAM_POLICY_NO_STATEMENTS_WITH_ADMIN_ACCESS"
  }


}

resource "aws_config_config_rule" "IAM_ROLE_MANAGED_POLICY_CHECK" {
  depends_on = ["aws_config_configuration_recorder.cc_config_recorder"]

  description = "Checks that AWS Identity and Access Management (IAM) policies in a list of policies are attached to all AWS roles. The rule is NON_COMPLIANT if the IAM managed policy is not attached to the IAM role."

  name            = "IAM_ROLE_MANAGED_POLICY_CHECK"
  source {
    owner             = "AWS"
    source_identifier = "IAM_ROLE_MANAGED_POLICY_CHECK"
  }


  # Comma-separated list of AWS managed policy ARNs.
  # managed_policy_names = ["managed_policy_names"]

}

resource "aws_config_config_rule" "IAM_ROOT_ACCESS_KEY_CHECK" {
  depends_on = ["aws_config_configuration_recorder.cc_config_recorder"]

  description = "Checks whether the root user access key is available. The rule is COMPLIANT if the user access key does not exist."

  name            = "IAM_ROOT_ACCESS_KEY_CHECK"
  source {
    owner             = "AWS"
    source_identifier = "IAM_ROOT_ACCESS_KEY_CHECK"
  }


}

resource "aws_config_config_rule" "IAM_USER_GROUP_MEMBERSHIP_CHECK" {
  depends_on = ["aws_config_configuration_recorder.cc_config_recorder"]

  description = "Checks whether IAM users are members of at least one IAM group."

  name            = "IAM_USER_GROUP_MEMBERSHIP_CHECK"
  source {
    owner             = "AWS"
    source_identifier = "IAM_USER_GROUP_MEMBERSHIP_CHECK"
  }


  # Comma-separated list of IAM groups in which IAM users must be members.
  # group_name = ["group_name"]

}

resource "aws_config_config_rule" "IAM_USER_MFA_ENABLED" {
  depends_on = ["aws_config_configuration_recorder.cc_config_recorder"]

  description = "Checks whether the AWS Identity and Access Management users have multi-factor authentication (MFA) enabled."

  name            = "IAM_USER_MFA_ENABLED"
  source {
    owner             = "AWS"
    source_identifier = "IAM_USER_MFA_ENABLED"
  }


}

resource "aws_config_config_rule" "IAM_USER_NO_POLICIES_CHECK" {
  depends_on = ["aws_config_configuration_recorder.cc_config_recorder"]

  description = "Checks that none of your IAM users have policies attached. IAM users must inherit permissions from IAM groups or roles."

  name            = "IAM_USER_NO_POLICIES_CHECK"
  source {
    owner             = "AWS"
    source_identifier = "IAM_USER_NO_POLICIES_CHECK"
  }


}

resource "aws_config_config_rule" "IAM_USER_UNUSED_CREDENTIALS_CHECK" {
  depends_on = ["aws_config_configuration_recorder.cc_config_recorder"]

  description = "Checks whether your AWS Identity and Access Management (IAM) users have passwords or active access keys that have not been used within the specified number of days you provided. Re-evaluating this rule within 4 hours of the first evaluation will have no effect on the results."

  name            = "IAM_USER_UNUSED_CREDENTIALS_CHECK"
  source {
    owner             = "AWS"
    source_identifier = "IAM_USER_UNUSED_CREDENTIALS_CHECK"
  }


  # Maximum number of days within which a credential must be used. The default value is 90 days.
  # max_credential_usage_age = ["max_credential_usage_age"]

}

resource "aws_config_config_rule" "MFA_ENABLED_FOR_IAM_CONSOLE_ACCESS" {
  depends_on = ["aws_config_configuration_recorder.cc_config_recorder"]

  description = "Checks whether AWS Multi-Factor Authentication (MFA) is enabled for all AWS Identity and Access Management (IAM) users that use a console password. The rule is COMPLIANT if MFA is enabled."

  name            = "MFA_ENABLED_FOR_IAM_CONSOLE_ACCESS"
  source {
    owner             = "AWS"
    source_identifier = "MFA_ENABLED_FOR_IAM_CONSOLE_ACCESS"
  }



}

resource "aws_config_config_rule" "ROOT_ACCOUNT_HARDWARE_MFA_ENABLED" {
  depends_on = ["aws_config_configuration_recorder.cc_config_recorder"]

  description = "Checks whether your AWS account is enabled to use multi-factor authentication (MFA) hardware device to sign in with root credentials. The rule is NON_COMPLIANT if any virtual MFA devices are permitted for signing in with root credentials."

  name            = "ROOT_ACCOUNT_HARDWARE_MFA_ENABLED"
  source {
    owner             = "AWS"
    source_identifier = "ROOT_ACCOUNT_HARDWARE_MFA_ENABLED"
  }


}

resource "aws_config_config_rule" "ROOT_ACCOUNT_MFA_ENABLED" {
  depends_on = ["aws_config_configuration_recorder.cc_config_recorder"]

  description = "Checks whether users of your AWS account require a multi-factor authentication (MFA) device to sign in with root credentials."

  name            = "ROOT_ACCOUNT_MFA_ENABLED"
  source {
    owner             = "AWS"
    source_identifier = "ROOT_ACCOUNT_MFA_ENABLED"
  }


}

resource "aws_config_config_rule" "SHIELD_ADVANCED_ENABLED_AUTORENEW" {
  depends_on = ["aws_config_configuration_recorder.cc_config_recorder"]

  description = "Checks whether AWS Shield Advanced is enabled in your AWS account and this subscription is set to automatically renew."

  name            = "SHIELD_ADVANCED_ENABLED_AUTORENEW"
  source {
    owner             = "AWS"
    source_identifier = "SHIELD_ADVANCED_ENABLED_AUTORENEW"
  }


}

resource "aws_config_config_rule" "SHIELD_DRT_ACCESS" {
  depends_on = ["aws_config_configuration_recorder.cc_config_recorder"]

  description = "Verify that DDoS response team (DRT) can access AWS account. The rule is NON_COMPLIANT if AWS Shield Advanced is enabled but the role for DRT access is not configured."

  name            = "SHIELD_DRT_ACCESS"
  source {
    owner             = "AWS"
    source_identifier = "SHIELD_DRT_ACCESS"
  }


}

# Storage

resource "aws_config_config_rule" "EBS_SNAPSHOT_PUBLIC_RESTORABLE_CHECK" {
  depends_on = ["aws_config_configuration_recorder.cc_config_recorder"]

  description = "Checks whether Amazon Elastic Block Store snapshots are not publicly restorable. The rule is NON_COMPLIANT if one or more snapshots with the RestorableByUserIds field is set to all. If this field is set to all, then Amazon EBS snapshots are public."

  name            = "EBS_SNAPSHOT_PUBLIC_RESTORABLE_CHECK"
  source {
    owner             = "AWS"
    source_identifier = "EBS_SNAPSHOT_PUBLIC_RESTORABLE_CHECK"
  }


}

resource "aws_config_config_rule" "EFS_ENCRYPTED_CHECK" {
  depends_on = ["aws_config_configuration_recorder.cc_config_recorder"]

  description = "Checks whether Amazon Elastic File System (Amazon EFS) is configured to encrypt the file data using AWS Key Management Service (AWS KMS). The rule is NON_COMPLIANT if the encrypted key is set to false on DescribeFileSystems or if the KmsKeyId key on DescribeFileSystems does not match the KmsKeyId parameter."

  name            = "EFS_ENCRYPTED_CHECK"
  source {
    owner             = "AWS"
    source_identifier = "EFS_ENCRYPTED_CHECK"
  }


  # (optional) Amazon Resource Name (ARN) of the AWS KMS key that is used to encrypt the Amazon EFS file system.
  # kms_key_id = ["kms_key_id"]

}

resource "aws_config_config_rule" "ELB_DELETION_PROTECTION_ENABLED" {
  depends_on = ["aws_config_configuration_recorder.cc_config_recorder"]

  description = "Checks whether Elastic Load Balancing has deletion protection enabled. The rule is NON_COMPLIANT if deletion_protection.enabled is false."

  name            = "ELB_DELETION_PROTECTION_ENABLED"
  source {
    owner             = "AWS"
    source_identifier = "ELB_DELETION_PROTECTION_ENABLED"
  }


}

resource "aws_config_config_rule" "EMR_MASTER_NO_PUBLIC_IP" {
  depends_on = ["aws_config_configuration_recorder.cc_config_recorder"]

  description = "Checks whether Amazon Elastic MapReduce (EMR) clusters' master nodes have public IPs. The rule is NON_COMPLIANT if the master node has a public IP."

  name            = "EMR_MASTER_NO_PUBLIC_IP"
  source {
    owner             = "AWS"
    source_identifier = "EMR_MASTER_NO_PUBLIC_IP"
  }


}

resource "aws_config_config_rule" "EMR_KERBEROS_ENABLED" {
  depends_on = ["aws_config_configuration_recorder.cc_config_recorder"]

  description = "Checks whether Amazon Elastic MapReduce (EMR) clusters' master nodes have public IPs. The rule is NON_COMPLIANT if the master node has a public IP."

  name            = "EMR_KERBEROS_ENABLED"
  source {
    owner             = "AWS"
    source_identifier = "EMR_MASTER_NO_PUBLIC_IP"
  }


  # (optional) Period for which Kerberos ticket issued by cluster's KDC is valid.
  # ticket_lifetime_in_hours = ["ticket_lifetime_in_hours"]

  # (optional) Kereberos realm name of the other realm in the trust relationship.
  # realm = ["realm"]

  # (optional) Domain name of the other realm in the trust relationship.
  # domain = ["domain"]

  # (optional) Fully qualified domain of the admin server in the other realm of the trust relationship.
  # admin_server = ["admin_server"]

  # (optional) Fully qualified domain of the KDC server in the other realm of the trust relationship.
  # kdc_server = ["kdc_server"]

}

resource "aws_config_config_rule" "S3_ACCOUNT_LEVEL_PUBLIC_ACCESS_BLOCKS" {
  depends_on = ["aws_config_configuration_recorder.cc_config_recorder"]

  description = "Checks whether the required public access block settings are configured from account level. The rule is only NON_COMPLIANT when the fields set below do not match the corresponding fields in the configuration item."

  name            = "S3_ACCOUNT_LEVEL_PUBLIC_ACCESS_BLOCKS"
  source {
    owner             = "AWS"
    source_identifier = "S3_ACCOUNT_LEVEL_PUBLIC_ACCESS_BLOCKS"
  }


  # (Optional) Either enforced (True) or not (False). The default is True.
  # ignore_public_acls = ["ignore_public_acls"]

  # (Optional) Either enforced (True) or not (False). The default is True.
  # block_public_policy = ["block_public_policy"]

  # (Optional) Either enforced (True) or not (False). The default is True.
  # block_public_acls = ["block_public_acls"]

  # (Optional) Either enforced (True) or not (False). The default is True.
  # restrict_public_buckets = ["restrict_public_buckets"]

}

resource "aws_config_config_rule" "S3_BUCKET_BLACKLISTED_ACTIONS_PROHIBITED" {
  depends_on = ["aws_config_configuration_recorder.cc_config_recorder"]

  description = "Checks that the Amazon Simple Storage Service bucket policy does not allow blacklisted bucket-level and object-level actions on resources in the bucket for principals from other AWS accounts. For example, the rule checks that the Amazon S3 bucket policy does not allow another AWS account to perform any s3:GetBucket* actions and s3:DeleteObject on any object in the bucket. The rule is NON_COMPLIANT if any blacklisted actions are allowed by the Amazon S3 bucket policy."

  name            = "S3_BUCKET_BLACKLISTED_ACTIONS_PROHIBITED"
  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_BLACKLISTED_ACTIONS_PROHIBITED"
  }


  # Comma-separated list of blacklisted action patterns, for example, s3:GetBucket* and s3:DeleteObject.
  # blacklisted_action_patterns = ["blacklisted_action_patterns"]

}

resource "aws_config_config_rule" "S3_BUCKET_LOGGING_ENABLED" {
  depends_on = ["aws_config_configuration_recorder.cc_config_recorder"]

  description = "Checks whether logging is enabled for your S3 buckets."

  name            = "S3_BUCKET_LOGGING_ENABLED"
  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_LOGGING_ENABLED"
  }


  # Target S3 bucket for storing server access logs.
  # target_bucket = ["target_bucket"]

  # Prefix of the target S3 bucket for storing server access logs.
  # target_prefix = ["target_prefix"]
}

resource "aws_config_config_rule" "S3_BUCKET_POLICY_GRANTEE_CHECK" {
  depends_on = ["aws_config_configuration_recorder.cc_config_recorder"]

  description = "Checks that the access granted by the Amazon S3 bucket is restricted by any of the AWS principals, federated users, service principals, IP addresses, or VPCs that you provide. The rule is COMPLIANT if a bucket policy is not present."

  name            = "S3_BUCKET_POLICY_GRANTEE_CHECK"
  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_POLICY_GRANTEE_CHECK"
  }


  # Comma-separated list of principals such as IAM User ARNs, IAM Role ARNs and AWS accounts, for example 'arn:aws:iam::111122223333:user/Alice, arn:aws:iam::444455556666:role/Bob, 123456789012'.
  # aws_princapls = ["aws_principals"]

  # Comma-separated list of principals such as IAM User ARNs, IAM Role ARNs and AWS accounts, for example 'arn:aws:iam::111122223333:user/Alice, arn:aws:iam::444455556666:role/Bob, 123456789012'.
  # service_principals = ["service_principals"]

  # Comma-separated list of identity providers for web identity federation such as Amazon Cognito and SAML identity providers. For example, you can provide as parameter 'cognito-identity.amazonaws.com, arn:aws:iam::111122223333:saml-provider/my-provider'.
  # federated_users = ["federated_users"]

  # Comma-separated list of CIDR formatted IP addresses, for example '10.0.0.1, 192.168.1.0/24, 2001:db8::/32'.
  # ip_address = ["ip_address"]

  # Comma-separated list of Amazon Virtual Private Cloud (Amazon VPC) IDs, for example 'vpc-1234abc0, vpc-ab1234c0’.
  # vpc_ids = ["vpc_ids"]

}

resource "aws_config_config_rule" "S3_BUCKET_POLICY_NOT_MORE_PERMISSIVE" {
  depends_on = ["aws_config_configuration_recorder.cc_config_recorder"]

  description = "Verifies that your Amazon Simple Storage Service bucket policies do not allow other inter-account permissions than the control Amazon S3 bucket policy that you provide."

  name            = "S3_BUCKET_POLICY_NOT_MORE_PERMISSIVE"
  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_POLICY_NOT_MORE_PERMISSIVE"
  }


  # Amazon S3 bucket policy that defines an upper bound on the permissions of your S3 buckets. The policy can be a maximum of 1024 characters long.
  # control_policy = ["control_policy"]

}

resource "aws_config_config_rule" "S3_BUCKET_PUBLIC_READ_PROHIBITED" {
  depends_on = ["aws_config_configuration_recorder.cc_config_recorder"]

  description = "Checks that your Amazon S3 buckets do not allow public read access. The rule checks the Block Public Access settings, the bucket policy, and the bucket access control list (ACL)."

  name            = "S3_BUCKET_PUBLIC_READ_PROHIBITED"
  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_PUBLIC_READ_PROHIBITED"
  }




}

resource "aws_config_config_rule" "S3_BUCKET_PUBLIC_WRITE_PROHIBITED" {
  depends_on = ["aws_config_configuration_recorder.cc_config_recorder"]

  description = "Checks that your Amazon S3 buckets do not allow public write access. The rule checks the Block Public Access settings, the bucket policy, and the bucket access control list (ACL)."

  name            = "S3_BUCKET_PUBLIC_WRITE_PROHIBITED"
  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_PUBLIC_WRITE_PROHIBITED"
  }


}

resource "aws_config_config_rule" "S3_BUCKET_REPLICATION_ENABLED" {
  depends_on = ["aws_config_configuration_recorder.cc_config_recorder"]

  description = "Checks whether S3 buckets have cross-region replication enabled."

  name            = "S3_BUCKET_REPLICATION_ENABLED"
  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_REPLICATION_ENABLED"
  }


}

resource "aws_config_config_rule" "S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED" {
  depends_on = ["aws_config_configuration_recorder.cc_config_recorder"]

  description = "Checks that your Amazon S3 bucket either has Amazon S3 default encryption enabled or that the S3 bucket policy explicitly denies put-object requests without server side encryption."

  name            = "S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED"
  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED"
  }


}

resource "aws_config_config_rule" "S3_BUCKET_SSL_REQUESTS_ONLY" {
  depends_on = ["aws_config_configuration_recorder.cc_config_recorder"]

  description = "Checks whether S3 buckets have policies that require requests to use Secure Socket Layer (SSL)."

  name            = "S3_BUCKET_SSL_REQUESTS_ONLY"
  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_SSL_REQUESTS_ONLY"
  }


}
resource "aws_config_config_rule" "S3_BUCKET_VERSIONING_ENABLED" {
  depends_on = ["aws_config_configuration_recorder.cc_config_recorder"]

  description = "Checks whether versioning is enabled for your S3 buckets. Optionally, the rule checks if MFA delete is enabled for your S3 buckets."

  name            = "S3_BUCKET_VERSIONING_ENABLED"
  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_VERSIONING_ENABLED"
  }


  # MFA delete is enabled for your S3 buckets.
  # is_mfa_delete_enabled = ["is_mfa_delete_enabled"]

}

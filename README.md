# security-as-code
An out-of-the-box solution that provides security monitoring and guardrails for your AWS accounts through Infrastructure as Code.   

## Summary

This tool is designed to provided engineering teams a way to include security monitoring and guardrails into the deployment pipeline of any new enviroment that is stood up.


## implementation


##### AWS Config Managed Rules: 

All 245 AWS config managed rules have bee converted into Terraform. Rules can be configured and deployed as needed.  

https://docs.aws.amazon.com/config/latest/developerguide/managed-rules-by-aws-config.html

##### GuardDuty:

GuardDuty is an AWS managed service used for threat detection and security monitoring to protect your aws account. A GuardDuty detector is included in this stack to enable security monitoring in your account. 


## Coming Soon 

* Custom rules
* Sentinal policies for Terraform

## Deployment Requirments 

1. AWS account 
2. Terraform 0.12 or greater 

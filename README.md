# CSPM-AWS-AutoRemediation – CSPM security violation findings Auto-Remediation framework for AWS

The solution is auto-remediation framework for the security standards violation findings discovered by Netskope Cloud Security Posture Management (CSPM).

Netskope CSPM continuously assess public cloud deployments to mitigate risk, detect threats, scan and protect sensitive data and monitor for regulatory compliance. Netskope simplifies the discovery of security misconfigurations across your clouds. Netskope Auto-Remediation framework for AWS enables you to automatically mitigate the risk associated with these misconfigurations in your AWS cloud environment. 

Netskope CSPM security assessment results for such security benchmark standards as NIST, CIS, PCI DSS, as well as for your custom rules are available via the View Security Assessment Violations Netskope API. 
Netskope auto-Remediation solution for AWS deploys the set of AWS Lambada functions that query the above Netskope API on the scheduled intervals and mitigate supported violations automatically. 
You can deploy the framework as is or customize it to mitigate other security violations and to meet your specific organization’s security requirements. 

![](.//media/AWS-autoremediation.png)

Note, that you need to deploy this solution in each AWS region you opted in for. It’s recommended to deploy the remediation functions on the delegated security management account. You can choose to deploy them on the same account that’s been used as delegated administrator for Amazon GuardDuty, AWS Security Hub, or another delegated AWS account. Following AWS best security practices, it’s not recommended to deploy the solution on the AWS Organization Management account. Deployment of the remediation functions done using AWS-autoremediation CloudFormation template.
To remediate security violations findings across all your organization’s accounts, you need to deploy the cross-account AWS IAM roles on all accounts, including the delegated security management account. Cross-account roles deployed using AWS-autoremediation-target CloudFormation template. You can deploy it using AWS CloudFormation StackSet or using your cloud orchestration tools. 
As a pre-requisite, you need to enable AWS Systems Manager (AWS SSM) on all your accounts and AWS regions. AWS SSM Automation used to remediate violations for such compliance rules as rule 4.1 of the CIS AWS Foundations standard “Ensure no security groups allow ingress from 0.0.0.0/0 to port 22“.


# Deployment steps.
1.  Deploy the AWS-autoremediation CloudFormation stack on the delegate security management account. 

    a.  Clone this repository to your machine. 
```
    git clone https://github.com/netskopeoss/CSPM-AWS-AutoRemediation.git
```
    b.  Change the region to the one you are deploring the solution. 
    c.  In the AWS CloudFormation management console click Create Stack and choose With new resources (standard).
    d.  Choose Upload a template file and click on Choose file.
    e.  Choose the AWS-autoremediation.yaml from the disk and click Next.
    f.  Enter the stack name and the parameters for your deployment:

      NetskopeAPIToken – the secret access token to access Netskope API v1. The solution stores this token in AWS Secrets Manager encrypted with AWS KMS

      NetskopeTenantFQDN – your Netskope tenant FQDN. For example, myorg.goskope.com

    g.  Choose the remediations you'd like to deploy and click Next.
    h.  Optionally, enter the Tags for your CloudFormation stack and click Next.
    i.  Acknowledge creating IAM resources and click Create stack.

2.  Deploy the AWS-autoremediation-target CloudFormation stack on each of your organization’s accounts, including the Delegated Auto-Remediation account. 
You can deploy it using AWS CloudFormation StackSet or using your own automation tools.

To deploy it on the individual target account:

    a.  In the AWS CloudFormation management console click Create Stack and choose With new resources (standard).
    b.  Choose Upload a template file and click on Choose file.
    c.  Choose the AWS-autoremediation-target.yaml from the disk and click Next.
    d.  Enter the stack name and the parameters for your deployment:

      AWSManagementAccount – the account ID of your Delegated Auto-Remediation account where you deployed the AWS-autoremediation CloudFormation stack.

    e.  Click Next.
    f.  Optionally, enter the Tags for your CloudFormation stack and click Next.
    g.  Acknowledge creating IAM resources and click Create stack.
    
#  Supported AWS Auto-remediation Rules

## Service: CloudTrail
### 1. Secure audit trails so they cannot be altered: CloudTrail Log Files Lack Integrity Validation

- **Rule Definition**
  - CloudTrail should have Log File Validation Enabled

- **Auto-Remediation Overview**
  - The CloudTrail log file integrity validation process lets you know if a log file has been deleted or changed, or assert positively that no log files were delivered to your account during a given period of time.
  - The auto-remediation lambda function invokes the SSM runbook: [AWSConfigRemediation-EnableCloudTrailLogFileValidation](https://docs.aws.amazon.com/systems-manager-automation-runbooks/latest/userguide/automation-aws-enable-ctrail-log-validation.html) which enables log file validation for AWS CloudTrail.

- **Information from alert**
  - AWS Account ID
  - CloudTrail ARN
  - Region Name

- **Permissions Required**
  - cloudtrail:UpdateTrail
  - cloudtrail:GetTrail
  - ssm:StartAutomationExecution
  - ssm:GetAutomationExecution


## Service: EC2
### 2. Communications and control network protection: Ensure no security groups allow ingress from 0.0.0.0/0 to port 22

- **Rule Definition**
  - SecurityGroup should not have InboundRules with [ IPRanges with [ IP eq 0.0.0.0/0 ] and ( FromPort lte 22 and ToPort gte 22 ) and Protocol in ("-1", "tcp") ]

- **Auto-Remediation Overview**
  - The auto-remediation lambda function invokes the SSM runbook: [AWS-DisablePublicAccessForSecurityGroup](https://docs.aws.amazon.com/systems-manager-automation-runbooks/latest/userguide/automation-aws-disablepublicaccessforsecuritygroup.html) which removes the inbound rule entry of Source  ‘0.0.0.0/0’ with port 22 and port 3389 from security groups
  - The same lambda function will be used for the security group inbound rule entry with source ‘0.0.0.0/0’ with port 22 and port 3389

- **Information from alert**
  - AWS Account ID
  - Security group Name
  - Region Name

- **Permissions Required**
  - ec2:DescribeSecurityGroupReferences
  - ec2:DescribeSecurityGroups
  - ec2:UpdateSecurityGroupRuleDescriptionsEgress
  - ec2:UpdateSecurityGroupRuleDescriptionsIngress
  - ec2:RevokeSecurityGroupIngress
  - ec2:RevokeSecurityGroupEgress
  - ssm:StartAutomationExecution
  - iam:PassRole

### 3. Communications and control network protection: Ensure no security groups allow ingress from 0.0.0.0/0 to port 3389

- **Rule Definition**
  - SecurityGroup should not have InboundRules with [ IPRanges with [ IP eq 0.0.0.0/0 ] and ( FromPort lte 3389 and ToPort gte 3389 ) and Protocol in ("-1", "udp", "tcp") ]



- **Auto-Remediation Overview**
  - The auto-remediation lambda function invokes the SSM runbook: [AWS-DisablePublicAccessForSecurityGroup](https://docs.aws.amazon.com/systems-manager-automation-runbooks/latest/userguide/automation-aws-disablepublicaccessforsecuritygroup.html) which removes the inbound rule entry of Source  ‘0.0.0.0/0’ with port 22 and port 3389 from security groups
  - The same lambda function will be used for the security group inbound rule entry with source ‘0.0.0.0/0’ with port 22 and port 3389

- **Information from alert**
  - AWS Account ID
  - Security group Name
  - Region Name

- **Permissions Required**
  - ec2:DescribeSecurityGroupReferences
  - ec2:DescribeSecurityGroups
  - ec2:UpdateSecurityGroupRuleDescriptionsEgress
  - ec2:UpdateSecurityGroupRuleDescriptionsIngress
  - ec2:RevokeSecurityGroupIngress
  - ec2:RevokeSecurityGroupEgress
  - ssm:StartAutomationExecution

### 4. Baseline network operations and data flows: Ensure VPC flow logging is enabled in all VPCs

- **Rule Definition**
  - VPC should have atleast one FlowLogs with [ id ]

- **Auto-Remediation Overview**
  - A flow log enables you to capture information about the IP traffic going to and from network interfaces in your VPC.
  - The auto-remediation lambda function creates the VPC flow logging with the cloud watch log group if it does not exist.

- **Information from alert**
  - AWS Account ID
  - VPC ID
  - Region Name

- **Permissions Required**
  - logs:CreateLogGroup
  - ec2:CreateFlowLogs
  - ec2:DescribeFlowLogs
  - iam:PassRole

### 5. Communications and control network protection: Ensure no rule exists which allows all ingress traffic in default Network ACL

- **Rule Definition**
  - NetworkACL should not have IsDefault eq true and Rules with [ RuleAction eq "allow" and Protocol eq "-1" and Egress eq False and CidrBlock eq 0.0.0.0/0 ]

- **Auto-Remediation Overview**
  - The auto-remediation lambda function removes the rule entry from the default network Access control list that allows all traffic ingress for all protocols.
  - The same lambda function will be used for the default network ACLs and the network ACLs which are associated with subnets.

- **Information from alert**
  - AWS Account ID
  - Network ACL ID
  - Region Name

- **Permissions Required**
  - ec2:DescribeNetworkAcls
  - ec2:DeleteNetworkAclEntry
  
### 6. Communications and control network protection: Ensure no rule exists which allows all ingress traffic in Network ACL which is associated with a subnet

- **Rule Definition**
  - NetworkACL should not have IsDefault eq true and Rules with [ RuleAction eq "allow" and Protocol eq "-1" and Egress eq False and CidrBlock eq 0.0.0.0/0 ]

- **Auto-Remediation Overview**
  - The auto-remediation lambda function removes the rule entry from the specified network Access control list that allows all traffic ingress for all protocols.
  - The same lambda function will be used for the default network ACLs and the network ACLs which are associated with subnets.

- **Information from alert**
  - AWS Account ID
  - Network ACL ID
  - Region Name

- **Permissions Required**
  - ec2:DescribeNetworkAcls
  - ec2:DeleteNetworkAclEntry

## Service: IAM
### 7. Remote access: Ensure access keys are rotated every 90 days or less.

- **Rule Definition**
  - IAMUser should not have  AccessKey with [ Active and LastRotatedTime isEarlierThan ( -90 , "days" ) ]

- **Auto-Remediation Overview**
  - The auto-remediation lambda function inactivates the access key which is older than 90 days for the user.

- **Information from alert**
  - AWS Account ID
  - Username
  - Region Name

- **Permissions Required**
  - iam:UpdateAccessKey
  - iam:ListAccessKeys


## Service: RDS
### 8. Access permissions and authorizations: Ensure RDS Instances do not have Publicly Accessible Snapshots

- **Rule Definition**
  - Ensure that** Relational Database Service (RDS) database instances should not have publicly accessible snapshots (i.e. shared with all AWS accounts and users).

- **Auto-Remediation Overview**
  - Publicly shared AWS RDS database snapshots give permission to both a) restore the snapshot and b) create database instances from it. If required, you can share your RDS snapshots with a particular AWS account without making them public.
  - The auto-remediation lambda function disables the public access of all snapshots of given database instances by modifying the snapshot’s attribute ‘restore’.

- **Information from alert**
  - AWS Account ID
  - Database Instance Name
  - Region Name

- **Required Permissions**
  - rds:DescribeDBSnapshots
  - rds:ModifyDBSnapshotAttribute
  - rds:DescribeDBSnapshotAttributes
  - rds:DescribeDBInstance
## Service: Redshift
### 9. Access permissions and authorizations: Ensure Redshift Clusters are not Publicly accessible

- **Rule Definition**
  - Amazon Redshift Clusters should not be publicly accessible.

- **Auto-Remediation Overview**
  - With a publicly accessible Amazon Redshift cluster, the selected Redshift cluster is publicly accessible from the Internet and widely exposed to security threats.
  - The auto-remediation lambda function invokes the SSM runbook: [AWSConfigRemediation-DisablePublicAccessToRedshiftCluster](https://docs.aws.amazon.com/systems-manager-automation-runbooks/latest/userguide/automation-aws-disable-redshift-public-access.html) which disables public accessibility for Amazon Redshift cluster.

- **Information from alert**
  - AWS Account ID
  - Redshift Cluster ID
  - Region Name

- **Required Permissions**
  - redshift:DescribeClusters
  - redshift:ModifyCluster
  - ssm:StartAutomationExecution
  - ssm:GetAutomationExecution
## Service: S3
### 10. Ensure S3 Bucket is not publicly accessible.

- **Rule Definition**
  - S3Bucket should not have Access eq "Public"

- **Auto-Remediation Overview**
  - Bucket access can be managed using IAM policies and access control lists (ACLs).
  - Block public access (bucket settings) is used to block public access given from policies or ACLs. It contains the following settings,
    - Block public access to buckets and objects granted through new access control lists (ACLs)
    - Block public access to buckets and objects granted through any access control lists (ACLs)
    - Block public access to buckets and objects granted through new public bucket or access point policies
    - Block public and cross-account access to buckets and objects through any public bucket or access point policies
  - The auto-remediation lambda function enables the ( ii ) and ( iv ) settings for the given bucket which disables the public access to the bucket.

- **Information from alert**
  - AWS Account ID
  - Bucket Name
  - Region Name

- **Permissions Required**
  - s3:GetBucketPublicAccessBlock
  - s3:PutBucketPublicAccessBlock

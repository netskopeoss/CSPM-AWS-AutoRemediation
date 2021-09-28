CSPM-AWS-AutoRemediation – CSPM security violation findings Auto-Remediation framework for AWS

The solution is auto-remediation framework for the security standards violation findings discovered by Netskope Cloud Security Posture Management (CSPM).

Netskope CSPM continuously assess public cloud deployments to mitigate risk, detect threats, scan and protect sensitive data and monitor for regulatory compliance. Netskope simplifies the discovery of security misconfigurations across your clouds. Netskope Auto-Remediation framework for AWS enables you to automatically mitigate the risk associated with these misconfigurations in your AWS cloud environment. 

Netskope CSPM security assessment results for such security benchmark standards as NIST, CIS, PCI DSS, as well as for your custom rules are available via the View Security Assessment Violations Netskope API. 
Netskope auto-Remediation solution for AWS deploys the set of AWS Lambada functions that query the above Netskope API on the scheduled intervals and mitigate supported violations automatically. 
You can deploy the framework as is or customize it to mitigate other security violations and to meet your specific organization’s security requirements. 

![](.//media/AWS-autoremediation.png)

Deployment steps.
1.  Deploy the AWS-autoremediation CloudFormation stack on the Delegated Auto-Remediation account. 

    a.  Clone this repository to your machine. 

    git clone https://github.com/netskopeoss/CSPM-AWS-AutoRemediation.git

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

To deploy it on the individual account:

    a.  In the AWS CloudFormation management console click Create Stack and choose With new resources (standard).
    b.  Choose Upload a template file and click on Choose file.
    c.  Choose the AWS-autoremediation-target.yaml from the disk and click Next.
    d.  Enter the stack name and the parameters for your deployment:

      AWSManagementAccount – the account ID of your Delegated Auto-Remediation account where you deployed the AWS-autoremediation CloudFormation stack.

    e.  Click Next.
    f.  Optionally, enter the Tags for your CloudFormation stack and click Next.
    g.  Acknowledge creating IAM resources and click Create stack.
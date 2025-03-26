# Centralized AWS Network Firewall deployment model with Pulumi
This example creates a full infrastructure with 2 workloads A and B in 2 VPCs spoke A and B, each contains 2 AZs to maintain high availability. The whole network is protected by AWS Network Firewall deployed by Centralized deployment model. 

## About the architecture
- The Centralized Network Firewall deployment model consists of 3 central VPCs: Ingress, Egress and Inspection VPC.
- Network Firewall is deployed in the Inspection VPC subnet as an endpoint to inspect the incoming and outgoing traffic.
- Network connectivity between VPCs is accomplished via AWS Transit Gateway. The Transit Gateway maintains a central routing table that is used to route traffic from the spoke VPCs to the internet. We also need to maintain routes so that return traffic from the internet can be routed back to the correct spoke VPC.
![Uploading image.png…]()

## Prerequisites
[1. Install Pulumi]([url](https://www.pulumi.com/docs/iac/download-install/))
[2. Configure AWS Credentials]([url](https://www.pulumi.com/registry/packages/aws/installation-configuration/))
[3. Install Python]([url](https://www.pulumi.com/docs/iac/languages-sdks/python/))

## Deploy the app
### Step 1: Initialize the project:
1. Create a new Pulumi stack:
`pulumi stack init`
2. Configure the AWS region to deploy into:
`pulumi config set aws:region ap-northeast-3`
3. Paste the __main__.py file to define the resources
4. Deploy the Pulumi stack
`pulumi up`

### Step 2: Test the app
1. Go to the ALB DNS name in the output
2. Test the workloads
3. Connect to instance workload-a1 by a prebuilt ssh-endpoint to check the connection to the internet

## Clean up
Once you're finished experimenting, you can destroy your stack and remove it to avoid incurring any additional cost:
```
pulumi destroy
pulumi stack rm
```

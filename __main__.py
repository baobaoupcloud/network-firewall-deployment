import pulumi
import pulumi_aws as aws

# AWS Region
aws_region = "ap-northeast-3"

# VPC Configuration
vpcs_config = {
    "ingress-vpc": "10.0.1.0/24",
    "egress-vpc": "10.0.2.0/24",
    "inspection-vpc": "10.0.3.0/24",
    "spoke-vpc-a": "10.0.4.0/24",
    "spoke-vpc-b": "10.0.5.0/24",
}

# Subnet Configuration
subnets_config = [
    ("sub-aza-tgw-ingress", "az a", "10.0.1.16/28", "ingress-vpc"),
    ("sub-aza-alb-ingress", "az a", "10.0.1.0/28", "ingress-vpc"),
    ("sub-aza-public-egress", "az a", "10.0.2.0/28", "egress-vpc"),
    ("sub-aza-tgw-egress", "az a", "10.0.2.16/28", "egress-vpc"),
    ("sub-aza-tgw-inspection", "az a", "10.0.3.16/28", "inspection-vpc"),
    ("sub-aza-firewall-inspection", "az a", "10.0.3.0/28", "inspection-vpc"),
    ("sub-aza-workload-a1", "az a", "10.0.4.0/28", "spoke-vpc-a"),
    ("sub-azb-workload-a2", "az b", "10.0.4.16/28", "spoke-vpc-a"),
    ("sub-aza-workload-b1", "az a", "10.0.5.0/28", "spoke-vpc-b"),
    ("sub-azb-workload-b2", "az b", "10.0.5.16/28", "spoke-vpc-b"),
    ("sub-aza-tgw-a1", "az a", "10.0.4.32/28", "spoke-vpc-a"),
    ("sub-azb-tgw-a2", "az b", "10.0.4.48/28", "spoke-vpc-a"),
    ("sub-aza-tgw-b1", "az a", "10.0.5.32/28", "spoke-vpc-b"),
    ("sub-azb-tgw-b2", "az b", "10.0.5.48/28", "spoke-vpc-b"),
]

# Create VPCs
vpcs = {}
for name, cidr in vpcs_config.items():
    vpcs[name] = aws.ec2.Vpc(
        name, 
        cidr_block=cidr, 
        enable_dns_support=True, 
        enable_dns_hostnames=True, 
        tags={"Name": name}
    )

# Create Subnets
subnets = {}
for name, az, cidr, vpc_name in subnets_config:
    subnets[name] = aws.ec2.Subnet(
        name, 
        vpc_id=vpcs[vpc_name].id, 
        cidr_block=cidr, 
        availability_zone=f"{aws_region}{az[-1]}", 
        tags={"Name": name}
    )

# Transit Gateway
transit_gateway = aws.ec2transitgateway.TransitGateway(
    "tgw", 
    tags={"Name": "transit-gateway"}
)

# Identify which VPCs should have TGW attachments
tgw_vpc_subnets = {}
for name, subnet in subnets.items():
    if "tgw" in name:
        vpc_name = subnets_config[[s[0] for s in subnets_config].index(name)][3]
        if vpc_name not in tgw_vpc_subnets:
            tgw_vpc_subnets[vpc_name] = []
        tgw_vpc_subnets[vpc_name].append(subnet.id)

# Create a TGW attachment per VPC, including all relevant subnets
tgw_attachments = {}
for vpc_name, subnet_ids in tgw_vpc_subnets.items():
    attachment = aws.ec2transitgateway.VpcAttachment(
        f"tgw-attach-{vpc_name}",
        transit_gateway_id=transit_gateway.id,
        vpc_id=vpcs[vpc_name].id,
        subnet_ids=subnet_ids,
        tags={"Name": f"tgw-attach-{vpc_name}"}
    )
    if vpc_name not in tgw_attachments:
        tgw_attachments[vpc_name] = []
    tgw_attachments[vpc_name].append(attachment)

# Security Group in each VPC
security_groups = {
    "spoke-vpc-a": aws.ec2.SecurityGroup(
        "security-group-workload-a",
        vpc_id=vpcs["spoke-vpc-a"].id,
        ingress=[
            aws.ec2.SecurityGroupIngressArgs(protocol="tcp", from_port=80, to_port=80, cidr_blocks=["0.0.0.0/0"]),
            aws.ec2.SecurityGroupIngressArgs(protocol="icmp", from_port=-1, to_port=-1, cidr_blocks=["10.0.0.0/8"]),
            aws.ec2.SecurityGroupIngressArgs(protocol="tcp", from_port=22, to_port=22, cidr_blocks=["0.0.0.0/0"])
        ],
        egress=[aws.ec2.SecurityGroupEgressArgs(protocol="-1", from_port=0, to_port=0, cidr_blocks=["0.0.0.0/0"])],
        tags={"Name": "security-group-workload-a"}
    ),
    "spoke-vpc-b": aws.ec2.SecurityGroup(
        "security-group-workload-b",
        vpc_id=vpcs["spoke-vpc-b"].id,
        ingress=[
            aws.ec2.SecurityGroupIngressArgs(protocol="tcp", from_port=80, to_port=80, cidr_blocks=["0.0.0.0/0"]),
            aws.ec2.SecurityGroupIngressArgs(protocol="icmp", from_port=-1, to_port=-1, cidr_blocks=["10.0.0.0/8"]),
            aws.ec2.SecurityGroupIngressArgs(protocol="tcp", from_port=22, to_port=22, cidr_blocks=["0.0.0.0/0"])
        ],
        egress=[aws.ec2.SecurityGroupEgressArgs(protocol="-1", from_port=0, to_port=0, cidr_blocks=["0.0.0.0/0"])],
        tags={"Name": "security-group-workload-b"}
    ),
}

security_group_alb = aws.ec2.SecurityGroup(
    "security-group-alb", 
    vpc_id=vpcs["ingress-vpc"].id,
    ingress=[
        aws.ec2.SecurityGroupIngressArgs(protocol="tcp", from_port=0, to_port=65535, cidr_blocks=["0.0.0.0/0"]),
        aws.ec2.SecurityGroupIngressArgs(protocol="icmp", from_port=-1, to_port=-1, cidr_blocks=["10.0.0.0/8"])
    ],
    egress=[aws.ec2.SecurityGroupEgressArgs(protocol="-1", from_port=0, to_port=0, cidr_blocks=["0.0.0.0/0"])],
    tags={"Name": "security-group-ingress-alb"}
)

# Workload instances
workload_a_instances =[]
workload_b_instances =[]
amazon_linux_ami = aws.ec2.get_ami(
    most_recent=True,
    owners=["amazon"],
    filters=[
        {"name": "name", "values": ["amzn2-ami-hvm-*-x86_64-gp2"]},
        {"name": "architecture", "values": ["x86_64"]},
        {"name": "root-device-type", "values": ["ebs"]},
        {"name": "virtualization-type", "values": ["hvm"]}
    ]
).id

for subnet_name, az, cidr, vpc_name in subnets_config:
    if "workload-a" in subnet_name:
        instance_name = subnet_name.replace("sub-aza-", "").replace("sub-azb-", "")
        security_group = security_groups[vpc_name]
        instance_a = aws.ec2.Instance(
            instance_name,
            instance_type="t3.micro",
            subnet_id=subnets[subnet_name].id,
            security_groups=[security_group.id],
            ami = amazon_linux_ami,
            user_data="""#!/bin/bash
            sleep 360
            sudo yum update -y
            sudo yum install -y git python3-pip
            sleep 30
            sudo pip3 install flask
            cd /home/ec2-user
            sudo git clone https://github.com/baobaoupcloud/nf-ws-workload-a.git
            sudo chown -R ec2-user:ec2-user nf-ws-workload-a
            cd nf-ws-workload-a
            nohup python3 quotes.py > quotes.log 2>&1 &
            """,
            tags={"Name": instance_name}
        )
        workload_a_instances.append(instance_a)
for subnet_name, az, cidr, vpc_name in subnets_config:
    if "workload-b" in subnet_name:
        instance_name = subnet_name.replace("sub-aza-", "").replace("sub-azb-", "")
        security_group = security_groups[vpc_name]
        instance_b = aws.ec2.Instance(
            instance_name,
            instance_type="t3.micro",
            subnet_id=subnets[subnet_name].id,
            security_groups=[security_group.id],
            ami = amazon_linux_ami,
            user_data="""#!/bin/bash
            sleep 360
            sudo yum update -y
            sudo yum install -y git python3-pip
            sleep 30
            sudo pip3 install flask
            cd /home/ec2-user
            sudo git clone https://github.com/baobaoupcloud/nf-ws-workload-b.git
            sudo chown -R ec2-user:ec2-user nf-ws-workload-b
            cd nf-ws-workload-b
            nohup python3 feedback.py > feedback.log 2>&1 &

            """,
            tags={"Name": instance_name}
        )
        workload_b_instances.append(instance_b)

# ALB
alb = aws.lb.LoadBalancer(
    "alb", 
    internal=False, 
    load_balancer_type="application", 
    security_groups=[security_group_alb.id], 
    subnets=[subnets["sub-aza-alb-ingress"].id], 
    tags={"Name": "application-load-balancer"}
)

# Target Group
tg_workload_a = aws.lb.TargetGroup(
    "tg-workload-a", 
    port=80, 
    protocol="HTTP", 
    vpc_id=vpcs["ingress-vpc"].id, 
    target_type="ip",
    health_check=aws.lb.TargetGroupHealthCheckArgs(        
        path="/workload-a",  
        protocol="HTTP",
        interval=30,
        timeout=5,
        healthy_threshold=5,
        unhealthy_threshold=3
    )
)
tg_workload_b = aws.lb.TargetGroup(
    "tg-workload-b", 
    port=80, 
    protocol="HTTP", 
    vpc_id=vpcs["ingress-vpc"].id, 
    target_type="ip",
    health_check=aws.lb.TargetGroupHealthCheckArgs(        
        path="/workload-b",  
        protocol="HTTP",
        interval=30,
        timeout=5,
        healthy_threshold=5,
        unhealthy_threshold=3
    )
)

# Register instances with target groups
for instance in workload_a_instances:
    aws.lb.TargetGroupAttachment(
        f"tg-attach-{instance._name}", 
        availability_zone="all",
        target_group_arn=tg_workload_a.arn, 
        target_id=instance.private_ip)

for instance in workload_b_instances:
    aws.lb.TargetGroupAttachment(
        f"tg-attach-{instance._name}",
        availability_zone="all", 
        target_group_arn=tg_workload_b.arn, 
        target_id=instance.private_ip)

# ALB Listener with Path-Based Routing and Default Selection Page
listener = aws.lb.Listener(
    "alb-listener", 
    load_balancer_arn=alb.arn, 
    port=80, protocol="HTTP", 
    default_actions=[
        aws.lb.ListenerDefaultActionArgs(
            type="fixed-response",
            fixed_response=aws.lb.ListenerDefaultActionFixedResponseArgs(
                content_type="text/html",
                message_body="""
                <html>
                <head><title>Welcome</title></head>
                <body style="font-family: Arial, sans-serif; text-align: center; background: #FFF3F3; padding: 20px;">
                    <h2 style="color: #FF4081;">Hey there!</h2>
                    <p style="font-size: 16px;">Pick what you'd like to do!</p>
                    <div style="display: flex; justify-content: center; gap: 15px;">
                        <a href='/workload-a' style="text-decoration: none; background: #FF69B4; color: white; padding: 10px 20px; border-radius: 5px;">Get a Quote</a>
                        <a href='/workload-b' style="text-decoration: none; background: #7B68EE; color: white; padding: 10px 20px; border-radius: 5px;">Rate Your Day</a>
                    </div>
                </body>
                </html>         
                """,
                status_code="200"
            )
        )
    ]
)

aws.lb.ListenerRule(
    "route-workload-a", 
    listener_arn=listener.arn, 
    priority=101, 
    conditions=[
        aws.lb.ListenerRuleConditionArgs(
            path_pattern=aws.lb.ListenerRuleConditionPathPatternArgs(values=["/workload-a"])
        )
    ], 
    actions=[
        aws.lb.ListenerRuleActionArgs(
            type="forward", 
            target_group_arn=tg_workload_a.arn
        )
    ]
)

aws.lb.ListenerRule(
    "route-workload-b", 
    listener_arn=listener.arn, 
    priority=102, 
    conditions=[
        aws.lb.ListenerRuleConditionArgs(
            path_pattern=aws.lb.ListenerRuleConditionPathPatternArgs(values=["/workload-b"])
        )
    ], 
    actions=[
        aws.lb.ListenerRuleActionArgs(
            type="forward", 
            target_group_arn=tg_workload_b.arn
        )
    ]
)

# Internet Gateways for Ingress and Egress VPCs
igws = {}
for vpc_name in ["ingress-vpc", "egress-vpc"]:
    igws[vpc_name] = aws.ec2.InternetGateway(
        f"igw-{vpc_name}",
        vpc_id=vpcs[vpc_name].id,
        tags={"Name": f"igw-{vpc_name}"}
    )

# NAT Gateway
eip = aws.ec2.Eip("eip", vpc=True)

nat_gateway = aws.ec2.NatGateway(
    "nat-gw",
    allocation_id=eip.id,
    subnet_id=subnets["sub-aza-public-egress"].id,
    tags={"Name": "nat-gw"}
)

# Network Firewall Rule Group
#   Allow most traffic rule group
allow_most = aws.networkfirewall.RuleGroup(
    "allow-tcp-udp-http-https",
    capacity=200,
    type="STATEFUL",
    rule_group={
        "rules_source": {
            "rules_string": """
            drop tcp any any -> 9.9.9.9/32 any (msg: "Drop TCP traffic to 9.9.9.9"; sid:1001; rev:1;)
            drop icmp any any -> 9.9.9.9/32 any (msg: "Drop ICMP traffic to 9.9.9.9"; sid:1002; rev:1;)
            pass icmp any any -> any any (msg: "Allow all ICMP packets"; sid:1003; rev:1;)
            pass tcp any any -> any any (msg: "Allow all TCP traffic"; sid:1004; rev:1;)
            pass udp any any -> any any (msg: "Allow all UDP traffic"; sid:1005; rev:1;)
            pass http any any -> any any (msg: "Allow all HTTP traffic"; sid:1006; rev:1;)
            """
        },
        "stateful_rule_options": {
            "rule_order": "STRICT_ORDER"
        }
    },
)

# Firewall Policy
firewall_policy = aws.networkfirewall.FirewallPolicy(
        "firewall-policy",
        aws.networkfirewall.FirewallPolicyArgs(
            firewall_policy=aws.networkfirewall.FirewallPolicyFirewallPolicyArgs(
                stateless_default_actions=["aws:forward_to_sfe"],
                stateless_fragment_default_actions=["aws:forward_to_sfe"],
                stateful_default_actions=["aws:drop_strict", "aws:alert_strict"],
                stateful_engine_options={"rule_order": "STRICT_ORDER"},
                stateful_rule_group_references=[
                    aws.networkfirewall.FirewallPolicyFirewallPolicyStatefulRuleGroupReferenceArgs(
                        priority=10,
                        resource_arn="arn:aws:network-firewall:ap-northeast-3:aws-managed:stateful-rulegroup/BotNetCommandAndControlDomainsStrictOrder"
                    ),
                    aws.networkfirewall.FirewallPolicyFirewallPolicyStatefulRuleGroupReferenceArgs(
                        priority=20,
                        resource_arn=allow_most.arn
                    )
                ]
            )
        ),
)

# Network Firewall 
network_firewall = aws.networkfirewall.Firewall(
    "network-firewall",
    vpc_id=vpcs["inspection-vpc"].id,
    firewall_policy_arn=firewall_policy.arn,
    subnet_mappings=[{"subnet_id": subnets["sub-aza-firewall-inspection"].id}],
    tags={"Name": "network-firewall"}
)

# Network Firewall Endpoint
firewall_status = network_firewall.firewall_statuses[0]
sync_state = firewall_status["sync_states"][0]
attachment = sync_state["attachments"][0]
nf_vpce_id = attachment["endpoint_id"]

# Create a CloudWatch Log Group for Network Firewall Logs
network_firewall_log_group = aws.cloudwatch.LogGroup(
    "network-firewall-logs",
    retention_in_days=7 
)

# Enable Logging for Network Firewall
firewall_logging_config = aws.networkfirewall.LoggingConfiguration(
    "firewall-logging-config",
    firewall_arn=network_firewall.arn,
    logging_configuration=aws.networkfirewall.LoggingConfigurationLoggingConfigurationArgs(
        log_destination_configs=[
            aws.networkfirewall.LoggingConfigurationLoggingConfigurationLogDestinationConfigArgs(
                log_destination_type="CloudWatchLogs",
                log_destination={
                    "logGroup": network_firewall_log_group.name
                },
                log_type="ALERT"
            ),
            aws.networkfirewall.LoggingConfigurationLoggingConfigurationLogDestinationConfigArgs(
                log_destination_type="CloudWatchLogs",
                log_destination={
                    "logGroup": network_firewall_log_group.name,
                },
                log_type="FLOW"
            )
        ]
    )
)

# Route table subnet
rt_spoke_vpc_a = aws.ec2.RouteTable(
    "rt-spoke-vpc-a",
    vpc_id=vpcs["spoke-vpc-a"].id,
    routes=[
        aws.ec2.RouteTableRouteArgs(
            cidr_block="10.0.4.0/24",
            local_gateway_id="local",
        ),
        aws.ec2.RouteTableRouteArgs(
            cidr_block="0.0.0.0/0",
            transit_gateway_id=transit_gateway.id
        )
    ],
    tags={"Name": "rt-spoke-vpc-a"}
)
aws.ec2.RouteTableAssociation(
    "rt-spoke-vpc-a1-association",
    route_table_id=rt_spoke_vpc_a.id,
    subnet_id=subnets["sub-aza-workload-a1"].id
)
aws.ec2.RouteTableAssociation(
    "rt-spoke-vpc-a2-association",
    route_table_id=rt_spoke_vpc_a.id,
    subnet_id=subnets["sub-azb-workload-a2"].id
)

rt_spoke_vpc_b = aws.ec2.RouteTable(
    "rt-spoke-vpc-b",
    vpc_id=vpcs["spoke-vpc-b"].id,
    routes=[
        aws.ec2.RouteTableRouteArgs(
            cidr_block="10.0.5.0/24",
            local_gateway_id="local",
        ),
        aws.ec2.RouteTableRouteArgs(
            cidr_block="0.0.0.0/0",
            transit_gateway_id=transit_gateway.id
        )
    ],
    tags={"Name": "rt-spoke-vpc-b"}
)
aws.ec2.RouteTableAssociation(
    "rt-spoke-vpc-b1-association",
    route_table_id=rt_spoke_vpc_b.id,
    subnet_id=subnets["sub-aza-workload-b1"].id
)
aws.ec2.RouteTableAssociation(
    "rt-spoke-vpc-b2-association",
    route_table_id=rt_spoke_vpc_b.id,
    subnet_id=subnets["sub-azb-workload-b2"].id
)

rt_alb = aws.ec2.RouteTable(
    "rt-alb",
    vpc_id=vpcs["ingress-vpc"].id,
    routes=[
        aws.ec2.RouteTableRouteArgs(
            cidr_block="10.0.1.0/24",
            local_gateway_id="local",
        ),
        aws.ec2.RouteTableRouteArgs(
            cidr_block="10.0.0.0/8",
            transit_gateway_id=transit_gateway.id,
        ),
        aws.ec2.RouteTableRouteArgs(
            cidr_block="0.0.0.0/0",
            gateway_id=igws["ingress-vpc"].id
        )
    ],
    tags={"Name": "rt-alb"}
)
aws.ec2.RouteTableAssociation(
    "rt-alb-association",
    route_table_id=rt_alb.id,
    subnet_id=subnets["sub-aza-alb-ingress"].id 
)

rt_nat = aws.ec2.RouteTable(
    "rt-nat",
    vpc_id=vpcs["egress-vpc"].id,
    routes=[
        aws.ec2.RouteTableRouteArgs(
            cidr_block="10.0.2.0/24",
            local_gateway_id="local",
        ),
        aws.ec2.RouteTableRouteArgs(
            cidr_block="10.0.0.0/8",
            transit_gateway_id=transit_gateway.id,
        ),
        aws.ec2.RouteTableRouteArgs(
            cidr_block="0.0.0.0/0",
            gateway_id=igws["egress-vpc"].id
        )
    ],
    tags={"Name": "rt-nat"}
)
aws.ec2.RouteTableAssociation(
    "rt-nat-association",
    route_table_id=rt_nat.id,
    subnet_id=subnets["sub-aza-public-egress"].id 
)

rt_firewall = aws.ec2.RouteTable(
    "firewall-rt",
    vpc_id=vpcs["inspection-vpc"].id,
    routes=[
        aws.ec2.RouteTableRouteArgs(
            cidr_block="10.0.3.0/24",
            local_gateway_id="local",
        ),
        aws.ec2.RouteTableRouteArgs(
            cidr_block="0.0.0.0/0",
            transit_gateway_id=transit_gateway.id,
        ),
    ],
    tags={"Name": "firewall-route-table"}
)
aws.ec2.RouteTableAssociation(
    "rt-firewall-association",
    route_table_id=rt_firewall.id,
    subnet_id=subnets["sub-aza-firewall-inspection"].id
)

rt_tgw_ingress = aws.ec2.RouteTable(
    "rt-tgw-ingress",
    vpc_id=vpcs["ingress-vpc"].id,
    routes=[
        aws.ec2.RouteTableRouteArgs(
            cidr_block="10.0.1.0/24",
            local_gateway_id="local",
        ),
        aws.ec2.RouteTableRouteArgs(
            cidr_block="10.0.0.0/8",
            transit_gateway_id=transit_gateway.id
        )
    ],
    tags={"Name": "rt-tgw-ingress"}
)
aws.ec2.RouteTableAssociation(
    "rt-tgw-ingress-association",
    route_table_id=rt_tgw_ingress.id,
    subnet_id=subnets["sub-aza-tgw-ingress"].id
)

rt_tgw_inspection = aws.ec2.RouteTable(
    "rt-tgw-inspection",
    vpc_id=vpcs["inspection-vpc"].id,
    routes=[
        aws.ec2.RouteTableRouteArgs(
            cidr_block="10.0.3.0/24",
            local_gateway_id="local",
        ),
        aws.ec2.RouteTableRouteArgs(
            cidr_block="0.0.0.0/0",
            vpc_endpoint_id=nf_vpce_id
        )
    ],
    tags={"Name": "rt-tgw-inspection"}
)
aws.ec2.RouteTableAssociation(
    "rt-tgw-inspection-association",
    route_table_id=rt_tgw_inspection.id,
    subnet_id=subnets["sub-aza-tgw-inspection"].id
)

rt_tgw_egress = aws.ec2.RouteTable(
    "rt-tgw-egress",
    vpc_id=vpcs["egress-vpc"].id,
    routes=[
        aws.ec2.RouteTableRouteArgs(
            cidr_block="10.0.2.0/24",
            local_gateway_id="local",
        ),
        aws.ec2.RouteTableRouteArgs(
            cidr_block="10.0.0.0/8",
            transit_gateway_id=transit_gateway.id
        ),
        aws.ec2.RouteTableRouteArgs(
            cidr_block="0.0.0.0/0",
            gateway_id=nat_gateway.id 
        )
    ],
    tags={"Name": "rt-tgw-egress"}
)
aws.ec2.RouteTableAssociation(
    "rt-tgw-egress-association",
    route_table_id=rt_tgw_egress.id,
    subnet_id=subnets["sub-aza-tgw-egress"].id
)

# Transit Gateway Route Table

tgw_central_route_table = aws.ec2transitgateway.RouteTable(
    "tgw-central-route-table",
    transit_gateway_id=transit_gateway.id,
    tags={"Name": "tgw-central-route-table"}
)
tgw_inspection_route_table = aws.ec2transitgateway.RouteTable(
    "tgw-inspection-route-table",
    transit_gateway_id=transit_gateway.id,
    tags={"Name": "tgw-inspection-route-table"}
)

# Route tgw-route-table to each tgw vpc attachment   
aws.ec2transitgateway.Route(
    "tgw-central-route-table",
    destination_cidr_block="0.0.0.0/0",
    transit_gateway_route_table_id=tgw_central_route_table.id,
    transit_gateway_attachment_id=tgw_attachments["inspection-vpc"][0].id
)
inspection_route = [
    aws.ec2transitgateway.Route(
        "tgw-inspection-route-1",
        destination_cidr_block="0.0.0.0/0",
        transit_gateway_route_table_id=tgw_inspection_route_table.id,
        transit_gateway_attachment_id=tgw_attachments["egress-vpc"][0].id
    ),
    aws.ec2transitgateway.Route(
        "tgw-inspection-route-2",
        destination_cidr_block="10.0.1.0/24",
        transit_gateway_route_table_id=tgw_inspection_route_table.id,
        transit_gateway_attachment_id=tgw_attachments["ingress-vpc"][0].id
    ),
    aws.ec2transitgateway.Route(
        "tgw-inspection-route-3",
        destination_cidr_block="10.0.4.0/24",
        transit_gateway_route_table_id=tgw_inspection_route_table.id,
        transit_gateway_attachment_id=tgw_attachments["spoke-vpc-a"][0].id
    ),
    aws.ec2transitgateway.Route(
        "tgw-inspection-route-4",
        destination_cidr_block="10.0.5.0/24",
        transit_gateway_route_table_id=tgw_inspection_route_table.id,
        transit_gateway_attachment_id=tgw_attachments["spoke-vpc-b"][0].id
    )
]

central_vpcs = ["ingress-vpc", "egress-vpc", "spoke-vpc-a", "spoke-vpc-b"]
for vpc_name, attachments in tgw_attachments.items():
    if vpc_name in central_vpcs:  
        if attachments: 
            for attachment in attachments:  
                aws.ec2transitgateway.RouteTableAssociation(
                    f"tgw-central-rt-association-{vpc_name}",
                    transit_gateway_route_table_id=tgw_central_route_table.id,
                    transit_gateway_attachment_id=attachment.id,
                    replace_existing_association=True  
                )


aws.ec2transitgateway.RouteTableAssociation(
    "tgw-inspection-rt-association",
    transit_gateway_route_table_id=tgw_inspection_route_table.id,
    transit_gateway_attachment_id=tgw_attachments["inspection-vpc"][0].id,
    replace_existing_association=True
)

instance_connect_endpoint = aws.ec2transitgateway.InstanceConnectEndpoint(
    "ssh-endpoint",
    subnet_id=subnets["sub-aza-workload-a1"].id,
    preserve_client_ip=True,
    security_group_ids=[security_groups["spoke-vpc-a"].id],
    tags={"Name": "ssh-endpoint"}
)

pulumi.export("alb_dns_name", alb.dns_name)

import boto3
from botocore.exceptions import ClientError

# Constants
AWS_REGION = "us-east-1"
VPC_NAME = "vpc-tp4"
VPC_CIDR = "10.0.0.0/16"
EC2_KEY_PAIR = "polystudent-ec2"
EC2_IMAGE_ID = "ami-069e612f612be3a2b"
EC2_TYPE = "t3.micro"
EC2_DISK_SIZE = 80
IAM_ROLE = "LabRoleEC2"
IAM_ROLE_ARN = "arn:aws:iam::665487683942:role/LabRoleEC2"
FLOW_LOGS_BUCKET = "polytp4s3"

# Initialize AWS clients
ec2_client = boto3.client('ec2', region_name=AWS_REGION)
cloudwatch_client = boto3.client('cloudwatch', region_name=AWS_REGION)

def create_vpc_with_dns():
    print(f"Creating VPC with CIDR {VPC_CIDR}...")
    vpc_response = ec2_client.create_vpc(CidrBlock=VPC_CIDR)
    vpc_id = vpc_response['Vpc']['VpcId']
    
    # Tag the VPC
    ec2_client.create_tags(
        Resources=[vpc_id],
        Tags=[{'Key': 'Name', 'Value': VPC_NAME}]
    )
    
    # Enable DNS features
    ec2_client.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={'Value': True})
    ec2_client.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={'Value': True})
    
    # Wait for VPC to be available
    ec2_client.get_waiter('vpc_available').wait(VpcIds=[vpc_id])
    print(f"✓ VPC created: {vpc_id}")
    return vpc_id

vpc_id = create_vpc_with_dns()

# Get first two availability zones
availability_zones = ec2_client.describe_availability_zones()['AvailabilityZones'][:2]
az1, az2 = availability_zones[0]['ZoneName'], availability_zones[1]['ZoneName']

print(f"\nCreating subnets in {az1} and {az2}...")

# Subnet configuration: (CIDR, AZ, is_public, name)
subnet_configs = [
    ("10.0.0.0/24", az1, True, f"{VPC_NAME} Public Subnet (AZ1)"),
    ("10.0.16.0/24", az2, True, f"{VPC_NAME} Public Subnet (AZ2)"),
    ("10.0.128.0/24", az1, False, f"{VPC_NAME} Private Subnet (AZ1)"),
    ("10.0.144.0/24", az2, False, f"{VPC_NAME} Private Subnet (AZ2)"),
]

subnet_ids = []
for cidr, az, is_public, name in subnet_configs:
    subnet = ec2_client.create_subnet(
        VpcId=vpc_id,
        CidrBlock=cidr,
        AvailabilityZone=az
    )
    subnet_id = subnet['Subnet']['SubnetId']
    subnet_ids.append(subnet_id)
    
    ec2_client.create_tags(Resources=[subnet_id], Tags=[{'Key': 'Name', 'Value': name}])
    
    if is_public:
        ec2_client.modify_subnet_attribute(
            SubnetId=subnet_id,
            MapPublicIpOnLaunch={'Value': True}
        )
    
    print(f"✓ Created subnet {subnet_id} ({name})")

public_subnet_az1 = subnet_ids[0]
public_subnet_az2 = subnet_ids[1]
private_subnet_az1 = subnet_ids[2]
private_subnet_az2 = subnet_ids[3]

# Create and attach Internet Gateway
print("\nSetting up Internet Gateway...")
igw_response = ec2_client.create_internet_gateway()
igw_id = igw_response['InternetGateway']['InternetGatewayId']
ec2_client.create_tags(Resources=[igw_id], Tags=[{'Key': 'Name', 'Value': f"{VPC_NAME}-igw"}])
ec2_client.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
print(f"✓ Internet Gateway {igw_id} attached to VPC")

# Configure public route table
print("\nConfiguring public routing...")
public_route_table = ec2_client.create_route_table(VpcId=vpc_id)['RouteTable']
public_rt_id = public_route_table['RouteTableId']

ec2_client.create_tags(
    Resources=[public_rt_id],
    Tags=[{'Key': 'Name', 'Value': f"{VPC_NAME} Public Routes"}]
)

# Add route to Internet Gateway
ec2_client.create_route(
    RouteTableId=public_rt_id,
    DestinationCidrBlock='0.0.0.0/0',
    GatewayId=igw_id
)

# Associate with public subnets
for subnet in [public_subnet_az1, public_subnet_az2]:
    ec2_client.associate_route_table(RouteTableId=public_rt_id, SubnetId=subnet)

print("✓ Public route table configured")

# Allocate Elastic IPs and create NAT Gateways
print("\nAllocating Elastic IPs for NAT Gateways...")
elastic_ips = []
for i in range(2):
    eip = ec2_client.allocate_address(Domain='vpc')
    elastic_ips.append(eip['AllocationId'])
    print(f"✓ Elastic IP {i+1} allocated: {eip['AllocationId']}")

# Create NAT Gateways in each public subnet
print("\nDeploying NAT Gateways...")
nat_gateway_ids = []
nat_configs = [
    (public_subnet_az1, elastic_ips[0], "AZ1"),
    (public_subnet_az2, elastic_ips[1], "AZ2")
]

for subnet, eip_alloc, az_label in nat_configs:
    nat_gw = ec2_client.create_nat_gateway(
        SubnetId=subnet,
        AllocationId=eip_alloc
    )
    nat_gw_id = nat_gw['NatGateway']['NatGatewayId']
    nat_gateway_ids.append(nat_gw_id)
    print(f"✓ NAT Gateway {az_label} creating: {nat_gw_id}")

# Wait for NAT Gateways to become available
print("Waiting for NAT Gateways to be ready...")
ec2_client.get_waiter('nat_gateway_available').wait(NatGatewayIds=nat_gateway_ids)
print("✓ All NAT Gateways are ready")

nat_gateway_az1 = nat_gateway_ids[0]
nat_gateway_az2 = nat_gateway_ids[1]

# Configure private route tables (one per AZ for high availability)
print("\nConfiguring private routing tables...")
private_route_configs = [
    (private_subnet_az1, nat_gateway_az1, "AZ1"),
    (private_subnet_az2, nat_gateway_az2, "AZ2")
]

for subnet, nat_gw, az_label in private_route_configs:
    # Create route table
    route_table = ec2_client.create_route_table(VpcId=vpc_id)['RouteTable']
    rt_id = route_table['RouteTableId']
    
    # Tag it
    ec2_client.create_tags(
        Resources=[rt_id],
        Tags=[{'Key': 'Name', 'Value': f"{VPC_NAME} Private Routes ({az_label})"}]
    )
    
    # Add default route through NAT Gateway
    ec2_client.create_route(
        RouteTableId=rt_id,
        DestinationCidrBlock='0.0.0.0/0',
        NatGatewayId=nat_gw
    )
    
    # Associate with private subnet
    ec2_client.associate_route_table(RouteTableId=rt_id, SubnetId=subnet)
    print(f"✓ Private route table for {az_label} configured")

# Create security group
print("\nCreating security group...")
security_group = ec2_client.create_security_group(
    GroupName=f"{VPC_NAME}-sg",
    Description="Security group for VPC instances - allows common protocols",
    VpcId=vpc_id
)
security_group_id = security_group['GroupId']
print(f"✓ Security group created: {security_group_id}")

# Define ingress rules
tcp_ports = [22, 80, 443, 53, 1433, 5432, 3306, 3389]  # SSH, HTTP, HTTPS, DNS, MSSQL, PostgreSQL, MySQL, RDP
udp_ports = [53, 1514]  # DNS, Syslog

ingress_rules = []

# Add TCP rules
for port in tcp_ports:
    ingress_rules.append({
        'IpProtocol': 'tcp',
        'FromPort': port,
        'ToPort': port,
        'IpRanges': [{'CidrIp': '0.0.0.0/0', 'Description': f'TCP port {port}'}]
    })

# Add UDP rules
for port in udp_ports:
    ingress_rules.append({
        'IpProtocol': 'udp',
        'FromPort': port,
        'ToPort': port,
        'IpRanges': [{'CidrIp': '0.0.0.0/0', 'Description': f'UDP port {port}'}]
    })

# Add Elasticsearch port range
ingress_rules.append({
    'IpProtocol': 'tcp',
    'FromPort': 9200,
    'ToPort': 9300,
    'IpRanges': [{'CidrIp': '0.0.0.0/0', 'Description': 'Elasticsearch'}]
})

ec2_client.authorize_security_group_ingress(
    GroupId=security_group_id,
    IpPermissions=ingress_rules
)
print("✓ Security group rules configured")

# Question 3.1: Enable VPC Flow Logs for rejected traffic
print("\nEnabling VPC Flow Logs...")
flow_log_destination = f"arn:aws:s3:::{FLOW_LOGS_BUCKET}/vpc-flow-logs/"
flow_log_response = ec2_client.create_flow_logs(
    ResourceType='VPC',
    ResourceIds=[vpc_id],
    TrafficType='REJECT',
    LogDestinationType='s3',
    LogDestination=flow_log_destination
)
if flow_log_response['Unsuccessful']:
    print(f"⚠ Flow log creation had issues: {flow_log_response['Unsuccessful']}")
else:
    print(f"✓ VPC Flow Logs enabled (capturing REJECT traffic to S3)")

# Question 3.2: Launch EC2 instances with IAM role
print("\n" + "="*60)
print("Launching EC2 Instances")
print("="*60)

# Define instance configurations
instance_specifications = [
    {"name": "Public-AZ1", "subnet": public_subnet_az1, "public_ip": True},
    {"name": "Public-AZ2", "subnet": public_subnet_az2, "public_ip": True},
    {"name": "Private-AZ1", "subnet": private_subnet_az1, "public_ip": False},
    {"name": "Private-AZ2", "subnet": private_subnet_az2, "public_ip": False},
]

launched_instances = []

for spec in instance_specifications:
    instance_name = f"{VPC_NAME}-{spec['name']}"
    print(f"\nLaunching instance: {instance_name}...")
    
    # Launch instance
    response = ec2_client.run_instances(
        ImageId=EC2_IMAGE_ID,
        InstanceType=EC2_TYPE,
        KeyName=EC2_KEY_PAIR,
        MinCount=1,
        MaxCount=1,
        IamInstanceProfile={'Name': IAM_ROLE},
        BlockDeviceMappings=[
            {
                'DeviceName': '/dev/sda1',
                'Ebs': {
                    'VolumeSize': EC2_DISK_SIZE,
                    'VolumeType': 'gp3',
                    'DeleteOnTermination': False
                }
            }
        ],
        NetworkInterfaces=[
            {
                'DeviceIndex': 0,
                'SubnetId': spec['subnet'],
                'Groups': [security_group_id],
                'AssociatePublicIpAddress': spec['public_ip']
            }
        ],
        TagSpecifications=[
            {
                'ResourceType': 'instance',
                'Tags': [{'Key': 'Name', 'Value': instance_name}]
            }
        ]
    )
    
    instance_id = response['Instances'][0]['InstanceId']
    launched_instances.append(instance_id)
    print(f"✓ Instance launched: {instance_id}")

# Wait for all instances to be running
print(f"\nWaiting for {len(launched_instances)} instances to reach running state...")
ec2_client.get_waiter('instance_running').wait(InstanceIds=launched_instances)
print("✓ All instances are now running")

# Question 3.2: Create CloudWatch alarms for network ingress monitoring
print("\n" + "="*60)
print("Configuring CloudWatch Alarms")
print("="*60)

INGRESS_THRESHOLD = 1000.0  # packets per second
MONITOR_PERIOD = 300  # 5 minutes
EVALUATION_PERIODS = 2

for instance_id in launched_instances:
    # Get instance name from tags
    tags = ec2_client.describe_tags(
        Filters=[
            {'Name': 'resource-id', 'Values': [instance_id]},
            {'Name': 'key', 'Values': ['Name']}
        ]
    )['Tags']
    instance_name = tags[0]['Value'] if tags else instance_id
    
    # Create alarm name
    alarm_name = f"NetworkIngress-High-{instance_id}"
    
    print(f"\nCreating alarm for {instance_name}...")
    cloudwatch_client.put_metric_alarm(
        AlarmName=alarm_name,
        AlarmDescription=f"Alert when network ingress packets exceed {INGRESS_THRESHOLD} pkt/s on {instance_name}",
        MetricName='NetworkPacketsIn',
        Namespace='AWS/EC2',
        Statistic='Average',
        Dimensions=[{'Name': 'InstanceId', 'Value': instance_id}],
        Period=MONITOR_PERIOD,
        EvaluationPeriods=EVALUATION_PERIODS,
        Threshold=INGRESS_THRESHOLD,
        ComparisonOperator='GreaterThanOrEqualToThreshold',
        TreatMissingData='notBreaching'
    )
    print(f"✓ Alarm created: {alarm_name}")

print("\n" + "="*60)
print("Infrastructure deployment complete!")
print("="*60)
print(f"\nVPC ID: {vpc_id}")
print(f"Instances launched: {len(launched_instances)}")
print(f"CloudWatch alarms configured: {len(launched_instances)}")
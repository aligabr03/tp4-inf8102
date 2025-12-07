import boto3
import json
import sys
from botocore.exceptions import ClientError

# Configs
REGION = "us-east-1"
BUCKET_MAIN = "polystudent3-lab4-bucket"
BUCKET_BACKUP = "polystudent3-lab4-bucket-backup"
ROLE_REPLICATION = "arn:aws:iam::665487683942:role/s3-replication-role"
KMS_KEY = "arn:aws:kms:us-east-1:665487683942:key/1b3c0a33-882a-47e1-9941-9c8c46382a23"
VPC_ID = "vpc-02f1dca159a017d73"
ACCOUNT_ID = "665487683942"
TRAIL = "Lab4S3CloudTrail"

# Instances boto3
s3 = boto3.client('s3', region_name=REGION)
ec2 = boto3.client('ec2', region_name=REGION)
iam = boto3.client('iam')
cloudtrail = boto3.client('cloudtrail', region_name=REGION)

def create_bucket(name):
    print(f"Creating bucket : {name}")
    s3.create_bucket(Bucket=name)
    print("Bucket created!")

def apply_security_to_bucket(name):    
    print(f"Applying security measures to bucket : {name}")

    # Block public access
    s3.put_public_access_block(Bucket=name,
        PublicAccessBlockConfiguration={
            'BlockPublicAcls': True,
            'IgnorePublicAcls': True, 
            'BlockPublicPolicy': True,
            'RestrictPublicBuckets': True
        })
    
    # KMS Encryption
    s3.put_bucket_encryption(Bucket=name,
        ServerSideEncryptionConfiguration={
            'Rules': [{'ApplyServerSideEncryptionByDefault': {
                'SSEAlgorithm': 'aws:kms',
                'KMSMasterKeyID': KMS_KEY
            }}]
        })
    
    # Versioning
    s3.put_bucket_versioning(Bucket=name,
        VersioningConfiguration={'Status': 'Enabled'})
    
    # HTTPS only policy
    pol = {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "DenyHTTP",
            "Effect": "Deny",
            "Principal": "*",
            "Action": "s3:*",
            "Resource": [f"arn:aws:s3:::{name}", f"arn:aws:s3:::{name}/*"],
            "Condition": {"Bool": {"aws:SecureTransport": "false"}}
        }]
    }
    s3.put_bucket_policy(Bucket=name, Policy=json.dumps(pol))
    print("Bucket securized!")


def setup_replication():
    config = {
        "Role": ROLE_REPLICATION,
        "Rules": [{
            "ID": "replicate-all",
            "Status": "Enabled",
            "Priority": 1,
            "DeleteMarkerReplication": {"Status": "Enabled"},
            "Filter": {"Prefix": ""},
            "Destination": {
                "Bucket": f"arn:aws:s3:::{BUCKET_BACKUP}",
                "StorageClass": "STANDARD"
            }
        }]
    }
    
    print("Setup replication...")
    s3.put_bucket_replication(Bucket=BUCKET_MAIN, ReplicationConfiguration=config)
    print("Replication successful!")

def get_bucket_policy(bucket):
    p = s3.get_bucket_policy(Bucket=bucket)['Policy']
    return json.loads(p)

def setup_cloudtrail():    
    policy = get_bucket_policy(BUCKET_MAIN)
    
    # CloudTrail statements
    policy['Statement'].append({
        "Sid": "CTAclCheck",
        "Effect": "Allow",
        "Principal": {"Service": "cloudtrail.amazonaws.com"},
        "Action": "s3:GetBucketAcl",
        "Resource": f"arn:aws:s3:::{BUCKET_MAIN}"
    })
    policy['Statement'].append({
        "Sid": "CTWrite",
        "Effect": "Allow", 
        "Principal": {"Service": "cloudtrail.amazonaws.com"},
        "Action": "s3:PutObject",
        "Resource": f"arn:aws:s3:::{BUCKET_MAIN}/AWSLogs/{ACCOUNT_ID}/*",
        "Condition": {"StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}}
    })
    
    # Updating the policy itself
    print(f"Updating CloudTrail bucket policy...")
    s3.put_bucket_policy(Bucket=BUCKET_MAIN, Policy=json.dumps(policy))
    print("CloudTrail bucket policy updated!")
    
    # Creating trail
    print("Creating trail...")
    cloudtrail.create_trail(
        Name=TRAIL,
        S3BucketName=BUCKET_MAIN,
        IsMultiRegionTrail=True,
        IncludeGlobalServiceEvents=True,
        EnableLogFileValidation=True
    )
    print("Trail created!")
    
    # Start logging
    print("Start logging")
    cloudtrail.start_logging(Name=TRAIL)
    

    # Configure S3 events
    print("Configure S3 events...")
    cloudtrail.put_event_selectors(
        TrailName=TRAIL,
        EventSelectors=[{
            'ReadWriteType': 'All',
            'IncludeManagementEvents': True,
            'DataResources': [{
                'Type': 'AWS::S3::Object',
                'Values': [f"arn:aws:s3:::{BUCKET_MAIN}/"]
            }]
        }]
    )
    print("S3 events configured")


def check_role():
    # Verifying existence of IAM role
    print("Verifying role...")
    try:
        r = iam.get_role(RoleName='LabRoleEC2')
        print(f"Role found: {r['Role']['Arn']}")
        return True
    except ClientError:
        print("ERROR: lab2role not found!")
        return False


if __name__ == "__main__":
    
    # Init checks
    if not check_role():
        sys.exit(1)
    
    # Question 2 :
    # Create and configure S3 bucket 
    create_bucket(BUCKET_MAIN)
    apply_security_to_bucket(BUCKET_MAIN)

    # Question 3.3.1 :
    # Create and configure S3 backup bucket
    create_bucket(BUCKET_BACKUP)
    apply_security_to_bucket(BUCKET_BACKUP)

    # Replication for 3.3.1 :
    setup_replication()

    # Question 3.3.2 :
    setup_cloudtrail()
    
    print("\n=== Setup termine! ===")
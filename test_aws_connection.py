"""
Test AWS Connection
Run this to verify AWS credentials, permissions, and connectivity
"""

import boto3
from botocore.exceptions import NoCredentialsError, ClientError, EndpointConnectionError


def test_aws_connection(region="us-east-1"):
    print("Testing AWS Connection")
    print("=" * 60)

    try:
        # Create a session (credentials picked from environment / AWS CLI)
        session = boto3.Session(region_name=region)

        # -------------------------
        # Test STS (Credentials)
        # -------------------------
        print("\n Testing AWS Credentials (STS)...")
        sts = session.client("sts")
        identity = sts.get_caller_identity()

        print(" AWS Credentials Valid")
        print(f"   Account ID : {identity['Account']}")
        print(f"   ARN        : {identity['Arn']}")
        print(f"   User ID    : {identity['UserId']}")

        # -------------------------
        # Test CloudTrail Access
        # -------------------------
        print("\nðŸ“œ Testing CloudTrail Access...")
        cloudtrail = session.client("cloudtrail")

        response = cloudtrail.lookup_events(MaxResults=1)
        print("âœ… CloudTrail Access OK")
        print(f"   Events fetched: {len(response.get('Events', []))}")

        # -------------------------
        # Test EC2 Access
        # -------------------------
        print("\nðŸ–¥ï¸ Testing EC2 Access...")
        ec2 = session.client("ec2")

        reservations = ec2.describe_instances().get("Reservations", [])
        instance_count = sum(len(r["Instances"]) for r in reservations)

        print(" EC2 Access OK")
        print(f"   EC2 instances found: {instance_count}")

        print("\n" + "=" * 60)
        print(" ALL TESTS PASSED")
        print(" AWS environment is ready for Cloud DFIR work")
        print("=" * 60)

        return True

    except NoCredentialsError:
        print("\n No AWS credentials found")
        print(" Fix:")
        print("   Run: aws configure")
        print("   Or set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY")
        return False

    except EndpointConnectionError:
        print("\n Network / Endpoint connection issue")
        print(" Fix:")
        print("   Check internet, VPN, proxy, or region")
        return False

    except ClientError as e:
        print("\n AWS Permission Error")
        print(f"   Error: {e}")
        print(" Fix:")
        print("   Ensure IAM user has required permissions")
        return False

    except Exception as e:
        print("\n Unexpected Error")
        print(f"   {e}")
        return False


if __name__ == "__main__":
    # Change region if needed (e.g., ap-south-1)
    test_aws_connection(region="us-east-1")




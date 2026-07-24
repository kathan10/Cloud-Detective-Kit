"""
Generate test CloudTrail activity
This creates some AWS events for you to investigate
"""

import boto3
import time
from datetime import datetime

def generate_test_activity():
    """Create some AWS activity for testing"""
    
    print(" Generating Test Activity")
    print("This will create some AWS events you can investigate")
    print("=" * 70)
    
    # Initialize clients
    s3 = boto3.client('s3')
    ec2 = boto3.client('ec2')
    iam = boto3.client('iam')
    
    print(f"\n Starting at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Activity 1: List S3 buckets (normal activity)
    print("\n1ï¸âƒ£  Normal Activity: Listing S3 buckets...")
    try:
        s3.list_buckets()
        print("   Done")
    except Exception as e:
        print(f"     {e}")
    time.sleep(2)
    
    # Activity 2: Check EC2 instances (reconnaissance)
    print("\n2ï¸âƒ£  Suspicious Activity: Reconnaissance - listing EC2 instances...")
    try:
        ec2.describe_instances()
        print("    Done")
    except Exception as e:
        print(f"   âš ï¸  {e}")
    time.sleep(2)
    
    # Activity 3: List IAM users (suspicious - checking for privileges)
    print("\n3ï¸âƒ£  Suspicious Activity: Listing IAM users...")
    try:
        iam.list_users()
        print("    Done")
    except Exception as e:
        print(f"   âš ï¸  {e}")
    time.sleep(2)
    
    # Activity 4: List security groups (looking for vulnerabilities)
    print("\n4ï¸âƒ£  Suspicious Activity: Checking security groups...")
    try:
        ec2.describe_security_groups()
        print("    Done")
    except Exception as e:
        print(f"     {e}")
    time.sleep(2)
    
    # Activity 5: Multiple rapid API calls (suspicious pattern)
    print("\n5ï¸âƒ£  Suspicious Pattern: Rapid API calls...")
    try:
        for i in range(5):
            s3.list_buckets()
            print(f"   Call {i+1}/5...", end=' ')
        print(" Done")
    except Exception as e:
        print(f"   âš ï¸  {e}")
    
    print("\n" + "=" * 70)
    print(" Test activity generated!")
    print(f" Completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    print("\n Now collect the evidence:")
    print("   python src/collectors/cloudtrail_collector.py")
    
    print("\n You'll see these events in CloudTrail:")
    print("   - ListBuckets (normal)")
    print("   - DescribeInstances (reconnaissance)")
    print("   - ListUsers (privilege checking)")
    print("   - DescribeSecurityGroups (vulnerability scan)")
    print("   - Multiple rapid ListBuckets (suspicious pattern)")
    print("=" * 70)

if __name__ == '__main__':
    generate_test_activity()




"""
Explore collected CloudTrail evidence
"""

import json
import sys
import glob
import os
from datetime import datetime
from collections import Counter

def explore_evidence(filename):
    """Explore what we collected"""
    
    print(" EXPLORING CLOUDTRAIL EVIDENCE")
    print("=" * 70)
    print(f"\nFile: {filename}\n")
    
    # Load the evidence
    try:
        with open(filename, 'r') as f:
            events = json.load(f)
    except FileNotFoundError:
        print(f" File not found: {filename}")
        print("\n Run: python src/collectors/cloudtrail_collector.py first")
        return
    
    print(f" Total Events Collected: {len(events)}\n")
    
    # Analyze event types
    print(" EVENT TYPES BREAKDOWN:")
    print("-" * 70)
    event_types = Counter(e.get('EventName', 'Unknown') for e in events)
    for i, (event, count) in enumerate(event_types.most_common(15), 1):
        print(f"{i:2}. {event:30} : {count:3} times")
    
    # Analyze by service
    print("\n SERVICES ACCESSED:")
    print("-" * 70)
    services = Counter(e.get('EventSource', 'Unknown').replace('.amazonaws.com', '') 
                      for e in events)
    for service, count in services.most_common(10):
        print(f"   {service:20} : {count:3} events")
    
    # Show timeline
    print("\n TIMELINE (First 10 Events):")
    print("-" * 70)
    for i, event in enumerate(events[:10], 1):
        time = event.get('EventTime', 'Unknown')
        name = event.get('EventName', 'Unknown')
        user = event.get('Username', 'Unknown')
        print(f"{i:2}. {time} | {name:30} | {user}")
    
    if len(events) > 10:
        print(f"\n   ... and {len(events) - 10} more events")
    
    # Show sample event
    print("\n SAMPLE EVENT (Full Detail):")
    print("-" * 70)
    if events:
        sample = events[0]
        print(json.dumps(sample, indent=2, default=str)[:1000] + "...")
    
    # Identify Scenario 1 activities
    print("\n SCENARIO 1 ACTIVITIES DETECTED:")
    print("-" * 70)
    
    scenario_events = {
        'S3 Activities': ['ListBuckets', 'GetBucketLocation', 'GetBucketAcl', 'GetBucketPolicy'],
        'EC2 Activities': ['DescribeInstances', 'DescribeSecurityGroups', 'DescribeRegions', 'DescribeKeyPairs'],
        'IAM Activities': ['GetUser', 'ListAccessKeys', 'ListRoles', 'GetRole', 'GetUserPolicy'],
        'RDS Activities': ['DescribeDBInstances'],
        'Lambda Activities': ['ListFunctions']
    }
    
    for category, event_names in scenario_events.items():
        found = [e for e in events if e.get('EventName') in event_names]
        if found:
            print(f"\n {category}: {len(found)} events")
            for event_name in set(e.get('EventName') for e in found):
                count = sum(1 for e in found if e.get('EventName') == event_name)
                print(f"   - {event_name}: {count}")
    
    # Analysis summary
    print("\n ANALYSIS SUMMARY:")
    print("-" * 70)
    print(f" Baseline activity captured: {len(events)} events")
    
    if events:
        earliest = min(e.get('EventTime', '') for e in events)
        latest = max(e.get('EventTime', '') for e in events)
        print(f" Time span: {earliest} to {latest}")
    
    print(f" Pattern: Exploratory browsing (normal administrator behavior)")
    print(f" Suspicious indicators: NONE (this is baseline)")
    
    print("\n" + "=" * 70)
    print("\n Next Steps:")
    print("   1. Review the events above")
    print("   2. Note the normal patterns")
    print("   3. Continue to Scenario 3 (attack simulation)")
    print("=" * 70)

if __name__ == '__main__':
    # Get latest evidence file
    evidence_files = glob.glob('evidence/cloudtrail_*.json')
    
    if not evidence_files:
        print(" No evidence files found!")
        print("\n First run: python src/collectors/cloudtrail_collector.py")
        print("   This will collect CloudTrail events")
        sys.exit(1)
    
    # Use most recent file
    latest_file = max(evidence_files, key=os.path.getctime)
    print(f" Using latest evidence file: {latest_file}\n")
    
    explore_evidence(latest_file)




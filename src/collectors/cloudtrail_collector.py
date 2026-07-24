"""
CloudTrail Evidence Collector
Collects CloudTrail logs for forensic analysis
"""

import boto3
from datetime import datetime, timedelta
import json
import os


class CloudTrailCollector:
    """Collects CloudTrail events from AWS account"""

    def __init__(self, region="us-east-1"):
        print(f"ðŸ”§ Initializing CloudTrail Collector for region: {region}")
        self.region = region
        self.client = boto3.client("cloudtrail", region_name=region)

    def collect_events(self, days_back=7, output_dir="evidence"):
        print("\nðŸ” Starting Evidence Collection")
        print(f"   Collecting last {days_back} days of CloudTrail events")
        print("=" * 60)

        start_time = datetime.utcnow() - timedelta(days=days_back)
        end_time = datetime.utcnow()

        print(
            f"   Time range: {start_time.strftime('%Y-%m-%d')} "
            f"to {end_time.strftime('%Y-%m-%d')}"
        )

        os.makedirs(output_dir, exist_ok=True)

        all_events = []
        next_token = None
        page_count = 0

        try:
            print("\nðŸ“¥ Downloading events...")

            while True:
                page_count += 1
                print(f"   Fetching page {page_count}...", end=" ")

                params = {
                    "StartTime": start_time,
                    "EndTime": end_time,
                    "MaxResults": 50,
                }

                if next_token:
                    params["NextToken"] = next_token

                response = self.client.lookup_events(**params)

                events = response.get("Events", [])
                all_events.extend(events)

                print(f"{len(events)} events (Total: {len(all_events)})")

                next_token = response.get("NextToken")
                if not next_token:
                    break

            print(f"\nâœ… Downloaded {len(all_events)} total events")

            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            filename = os.path.join(output_dir, f"cloudtrail_{timestamp}.json")

            print(f"\nðŸ’¾ Saving to file: {filename}")

            with open(filename, "w") as f:
                json.dump(all_events, f, indent=2, default=str)

            file_size = os.path.getsize(filename)

            summary = self.get_event_summary(all_events)
            self.print_summary(summary)

            return {
                "success": True,
                "events_collected": len(all_events),
                "filename": filename,
                "file_size_bytes": file_size,
                "summary": summary,
            }

        except Exception as e:
            print(f"\nâŒ ERROR: {e}")
            return {"success": False, "error": str(e)}

    def get_event_summary(self, events):
        summary = {
            "total_events": len(events),
            "event_types": {},
            "users": {},
            "regions": {},
            "source_ips": set(),
        }

        for event in events:
            event_name = event.get("EventName", "Unknown")
            summary["event_types"][event_name] = (
                summary["event_types"].get(event_name, 0) + 1
            )

            user = event.get("Username", "Unknown")
            summary["users"][user] = summary["users"].get(user, 0) + 1

            region = event.get("AwsRegion", "Unknown")
            summary["regions"][region] = summary["regions"].get(region, 0) + 1

            ip = event.get("SourceIPAddress")
            if ip:
                summary["source_ips"].add(ip)

        summary["source_ips"] = list(summary["source_ips"])
        return summary

    def print_summary(self, summary):
        print("\nðŸ“Š EVIDENCE SUMMARY")
        print("=" * 60)
        print(f"Total Events: {summary['total_events']}")
        print(f"Unique Event Types: {len(summary['event_types'])}")
        print(f"Unique Users: {len(summary['users'])}")
        print(f"Unique Regions: {len(summary['regions'])}")
        print(f"Unique Source IPs: {len(summary['source_ips'])}")
        print("=" * 60)


if __name__ == "__main__":
    print("ðŸš€ CloudTrail Evidence Collector")

    collector = CloudTrailCollector(region="us-east-1")
    result = collector.collect_events(days_back=7)

    if result["success"]:
        print("\nâœ… Collection successful")
        print(f"Events collected: {result['events_collected']}")
        print(f"Saved to: {result['filename']}")
    else:
        print("\nâŒ Collection failed")
        print(result["error"])




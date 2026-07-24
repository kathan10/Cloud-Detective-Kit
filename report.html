import json

def load_events(file_path):
    """
    Load and normalize CloudTrail events.
    Supports:
    - Raw CloudTrail logs (Records)
    - lookup-events API output (Events)
    - Plain list of events
    """

    with open(file_path, "r") as f:
        data = json.load(f)

    events = []

    # Case 1: Raw trail file
    if isinstance(data, dict) and "Records" in data:
        events = data["Records"]

    # Case 2: lookup-events output
    elif isinstance(data, dict) and "Events" in data:
        for e in data["Events"]:
            if "CloudTrailEvent" in e:
                try:
                    parsed = json.loads(e["CloudTrailEvent"])
                    events.append(parsed)
                except json.JSONDecodeError:
                    continue

    # Case 3: direct list
    elif isinstance(data, list):
        for e in data:
            if "CloudTrailEvent" in e:
                try:
                    parsed = json.loads(e["CloudTrailEvent"])
                    events.append(parsed)
                except json.JSONDecodeError:
                    continue
            else:
                events.append(e)

    else:
        raise ValueError("Unsupported CloudTrail log format")

    return events




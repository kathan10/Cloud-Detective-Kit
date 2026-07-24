MITRE_MAP = {

    "s3": {
        "ListBuckets": ("T1580", "Cloud Infrastructure Discovery"),
        "GetBucketAcl": ("T1580", "Cloud Infrastructure Discovery"),
        "GetBucketPolicy": ("T1580", "Cloud Infrastructure Discovery"),
    },

    "iam": {
        "CreateUser": ("T1136", "Create Account"),
        "CreateAccessKey": ("T1098", "Account Manipulation"),
        "AttachUserPolicy": ("T1098", "Account Manipulation"),
        "PutUserPolicy": ("T1098", "Account Manipulation"),
    },

    "ec2": {
        "RunInstances": ("T1496", "Resource Hijacking"),
        "StartInstances": ("T1496", "Resource Hijacking"),
        "StopInstances": ("T1496", "Resource Hijacking"),
        "TerminateInstances": ("T1496", "Resource Hijacking"),
    },

    "sts": {
    "AssumeRole": ("T1078", "Valid Accounts"),
    "GetCallerIdentity": ("T1087", "Account Discovery"),
    }
}


def map_to_mitre(event_name, event_source):

    # Extract service name (s3, iam, ec2)
    service = "unknown"

    if event_source:
        service = event_source.split(".")[0]

    # Check mapping
    if service in MITRE_MAP:
        if event_name in MITRE_MAP[service]:
            return MITRE_MAP[service][event_name]

    return ("N/A", "Unknown Technique")




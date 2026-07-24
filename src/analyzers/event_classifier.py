RECON_EVENTS = {
    "ListBuckets",
    "ListObjects",
    "DescribeInstances",
    "DescribeSecurityGroups"
}

HIGH_RISK_EVENTS = {
    "CreateUser",
    "AttachUserPolicy",
    "PutUserPolicy",
    "AuthorizeSecurityGroupIngress",
    "RunInstances"
}

def classify_event(event_name):
    if event_name in HIGH_RISK_EVENTS:
        return "HIGH-RISK"
    elif event_name in RECON_EVENTS:
        return "RECON"
    else:
        return "NORMAL"




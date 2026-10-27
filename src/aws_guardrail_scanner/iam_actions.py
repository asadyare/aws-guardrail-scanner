"""IAM actions the scanner calls.

``iam/scanner-policy.json`` must grant this set and nothing else. A test
compares the two so the published policy cannot drift from the code.
"""

REQUIRED_IAM_ACTIONS: tuple[str, ...] = (
    "cloudtrail:DescribeTrails",
    "cloudtrail:GetEventSelectors",
    "cloudtrail:GetTrailStatus",
    "ec2:DescribeSecurityGroups",
    "ec2:GetEbsEncryptionByDefault",
    "iam:GetAccountSummary",
    "iam:GetLoginProfile",
    "iam:ListAccessKeys",
    "iam:ListMFADevices",
    "iam:ListUsers",
    "s3:GetAccountPublicAccessBlock",
    "s3:GetBucketAcl",
    "s3:GetBucketEncryption",
    "s3:GetBucketLocation",
    "s3:GetBucketPolicyStatus",
    "s3:GetBucketPublicAccessBlock",
    "s3:ListAllMyBuckets",
    "sts:GetCallerIdentity",
)

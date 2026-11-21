"""Account-wide S3 exposure scan (a small, Prowler-style check set).

For every bucket in the account: is it (or can it become) public, is it encrypted, is it
versioned, does it insist on TLS - and, decisively, can an anonymous internet user actually
download an object? Read-only. Exit code 1 if any bucket is publicly readable.

    docker compose run --rm -e AWS_ACCESS_KEY_ID=111111111111 scan
"""

import json
import os
import sys
import urllib.error
import urllib.request

import boto3
from botocore.config import Config

ENDPOINT = os.environ.get("AWS_ENDPOINT_URL", "")
cfg = Config(s3={"addressing_style": "path"}, retries={"max_attempts": 2, "mode": "standard"})
s3 = boto3.client("s3", config=cfg)
s3control = boto3.client("s3control", config=cfg)
account = boto3.client("sts", config=cfg).get_caller_identity()["Account"]

ALL_USERS = "http://acs.amazonaws.com/groups/global/AllUsers"
findings = []  # (severity, bucket, check, detail)


def finding(sev, bucket, check, detail=""):
    findings.append((sev, bucket, check, detail))


def call(fn, default=None):
    try:
        return fn()
    except Exception:
        return default


def anonymous_get(url):
    try:
        with urllib.request.urlopen(url, timeout=5) as r:
            return r.status, r.read(200)
    except urllib.error.HTTPError as e:
        return e.code, b""
    except Exception as e:  # network error: not readable from here
        return None, str(e).encode()


acct_bpa = call(lambda: s3control.get_public_access_block(AccountId=account)["PublicAccessBlockConfiguration"], {})
acct_on = isinstance(acct_bpa, dict) and len(acct_bpa) == 4 and all(acct_bpa.values())
print(f"Account {account}: account-level Block Public Access {'ON' if acct_on else 'OFF'}")
if not acct_on:
    finding("MEDIUM", "(account)", "s3_account_level_public_access_blocks", "account-wide guardrail is off")

buckets = [b["Name"] for b in s3.list_buckets().get("Buckets", [])]
print(f"Buckets: {len(buckets)}\n")
for b in buckets:
    bpa = call(lambda: s3.get_public_access_block(Bucket=b)["PublicAccessBlockConfiguration"], {})
    if not (isinstance(bpa, dict) and len(bpa) == 4 and all(bpa.values())):
        finding("MEDIUM", b, "s3_bucket_level_public_access_block", json.dumps(bpa) or "not set")

    policy = call(lambda: json.loads(s3.get_bucket_policy(Bucket=b)["Policy"]), {}) or {}
    stmts = policy.get("Statement", [])
    public_stmts = [st.get("Sid", "?") for st in stmts
                    if st.get("Effect") == "Allow" and st.get("Principal") in ("*", {"AWS": "*"}) and not st.get("Condition")]
    if public_stmts:
        finding("CRITICAL", b, "s3_bucket_policy_public_access", f"Allow to Principal * (Sid {', '.join(public_stmts)})")
    if not any(st.get("Effect") == "Deny" and "aws:SecureTransport" in json.dumps(st.get("Condition", {})) for st in stmts):
        finding("MEDIUM", b, "s3_bucket_secure_transport_policy", "no deny for non-TLS requests")

    acl = call(lambda: s3.get_bucket_acl(Bucket=b), {}) or {}
    if any(g.get("Grantee", {}).get("URI") == ALL_USERS for g in acl.get("Grants", [])):
        finding("CRITICAL", b, "s3_bucket_public_acl", "ACL grants AllUsers")

    enc = call(lambda: s3.get_bucket_encryption(Bucket=b)["ServerSideEncryptionConfiguration"]["Rules"][0]
               ["ApplyServerSideEncryptionByDefault"]["SSEAlgorithm"])
    if enc != "aws:kms":
        finding("LOW", b, "s3_bucket_kms_encryption", f"default encryption: {enc or 'provider default only'}")
    if call(lambda: s3.get_bucket_versioning(Bucket=b).get("Status")) != "Enabled":
        finding("LOW", b, "s3_bucket_object_versioning", "versioning off")

    # The decisive test: try to read an object with no credentials at all.
    first = (call(lambda: s3.list_objects_v2(Bucket=b, MaxKeys=1), {}) or {}).get("Contents", [])
    if first and ENDPOINT:
        key = first[0]["Key"]
        status, body = anonymous_get(f"{ENDPOINT}/{b}/{key}")
        if status == 200:
            finding("CRITICAL", b, "anonymous_object_read",
                    f"GET {key} without credentials -> 200, first bytes: {body[:60].decode(errors='replace')!r}")
        else:
            print(f"  {b}: anonymous GET {key} -> {status} (denied)")

order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
for sev, b, check, detail in sorted(findings, key=lambda f: order[f[0]]):
    print(f"{sev:<8}  {b:<36}  {check:<38}  {detail}")
public = [f for f in findings if f[0] == "CRITICAL"]
print(f"\n{len(findings)} finding(s), {len(public)} critical")
sys.exit(1 if public else 0)

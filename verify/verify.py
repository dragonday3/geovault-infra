"""Check the deployed GeoVault stack against its security baseline.

Runs against whatever AWS_ENDPOINT_URL points at: the MiniStack emulator locally (default via
compose.yml), or real AWS later with read-only credentials. It only reads; it never changes
anything.

Each check names the control, what was found, and PASS/FAIL. Exit code 1 if anything fails.

What an emulator can and cannot show: these checks prove the *configuration* Terraform
produced (encryption on, public access blocked, IMDSv2 required...). They do not prove that
AWS *enforces* it - that needs the real-account audit (Prowler) in a later milestone.
"""

import json
import os
import sys

import boto3
from botocore.config import Config

ENV = os.environ.get("GEOVAULT_ENV", "local")
NAME = f"geovault-{ENV}"
PARAM_PATH = f"/geovault/{ENV}"

session = boto3.session.Session()
# Path-style S3 and few retries: an emulator answers fast or not at all.
CONFIG = Config(s3={"addressing_style": "path"}, retries={"max_attempts": 2, "mode": "standard"},
                connect_timeout=5, read_timeout=20)
s3, ec2, iam, kms, ssm, logs, trail, budgets, sts = (
    session.client(name, config=CONFIG)
    for name in ("s3", "ec2", "iam", "kms", "ssm", "logs", "cloudtrail", "budgets", "sts")
)

results: list[tuple[str, str, bool, str]] = []


def check(area: str, control: str, ok: bool, found: str = "") -> None:
    results.append((area, control, bool(ok), found))


def safe(fn, default=None):
    try:
        return fn()
    except Exception as exc:  # report, don't crash: a missing resource is a finding
        return default if default is not None else exc


# --- identity -------------------------------------------------------------------------------
account = sts.get_caller_identity()["Account"]
endpoint = os.environ.get("AWS_ENDPOINT_URL", "real AWS")
print(f"Target: {endpoint}  account {account}  region {session.region_name}  env {ENV}\n")

# --- KMS ------------------------------------------------------------------------------------
alias = next((a for a in kms.list_aliases()["Aliases"] if a["AliasName"] == f"alias/{NAME}"), None)
check("KMS", "customer-managed key exists", alias is not None, alias["AliasName"] if alias else "missing")
key_id = alias.get("TargetKeyId") if alias else None
key_arn = kms.describe_key(KeyId=key_id)["KeyMetadata"]["Arn"] if key_id else None
if key_id:
    rot = kms.get_key_rotation_status(KeyId=key_id)["KeyRotationEnabled"]
    check("KMS", "automatic key rotation on", rot, str(rot))

# --- account guardrail --------------------------------------------------------------------
s3control = session.client("s3control", config=CONFIG)
acct = safe(lambda: s3control.get_public_access_block(AccountId=account)["PublicAccessBlockConfiguration"], {})
check("Account", "account-level S3 Block Public Access on (all four)",
      isinstance(acct, dict) and len(acct) == 4 and all(acct.values()), json.dumps(acct) if isinstance(acct, dict) else str(acct))

# --- S3 -------------------------------------------------------------------------------------
for kind in ("photos", "logs"):
    bucket = f"{NAME}-{kind}-{account}"
    exists = not isinstance(safe(lambda b=bucket: s3.head_bucket(Bucket=b)), Exception)
    check(f"S3 {kind}", "bucket exists", exists, bucket)
    if not exists:
        continue
    bpa = safe(lambda b=bucket: s3.get_public_access_block(Bucket=b)["PublicAccessBlockConfiguration"], {})
    check(f"S3 {kind}", "all four Block Public Access settings on",
          isinstance(bpa, dict) and len(bpa) == 4 and all(bpa.values()), json.dumps(bpa))
    own = safe(lambda b=bucket: s3.get_bucket_ownership_controls(Bucket=b)["OwnershipControls"]["Rules"][0]["ObjectOwnership"], "")
    check(f"S3 {kind}", "ACLs disabled (BucketOwnerEnforced)", own == "BucketOwnerEnforced", str(own))
    ver = s3.get_bucket_versioning(Bucket=bucket).get("Status")
    check(f"S3 {kind}", "versioning enabled", ver == "Enabled", str(ver))
    enc = safe(lambda b=bucket: s3.get_bucket_encryption(Bucket=b)["ServerSideEncryptionConfiguration"]["Rules"][0]["ApplyServerSideEncryptionByDefault"], {})
    algo = enc.get("SSEAlgorithm") if isinstance(enc, dict) else None
    if kind == "photos":
        check("S3 photos", "SSE-KMS with the project key", algo == "aws:kms" and enc.get("KMSMasterKeyID") in (key_arn, key_id),
              f"{algo} {enc.get('KMSMasterKeyID', '') if isinstance(enc, dict) else ''}")
    else:
        check("S3 logs", "default encryption on (SSE-S3 for log delivery)", algo in ("AES256", "aws:kms"), str(algo))
    pol = safe(lambda b=bucket: json.loads(s3.get_bucket_policy(Bucket=b)["Policy"]), {})
    tls = any(
        st.get("Effect") == "Deny" and st.get("Condition", {}).get("Bool", {}).get("aws:SecureTransport") in ("false", False, ["false"])
        for st in (pol.get("Statement", []) if isinstance(pol, dict) else [])
    )
    check(f"S3 {kind}", "bucket policy denies non-TLS requests", tls)
    public_stmt = [
        st for st in (pol.get("Statement", []) if isinstance(pol, dict) else [])
        if st.get("Effect") == "Allow" and st.get("Principal") in ("*", {"AWS": "*"})
    ]
    check(f"S3 {kind}", "no Allow statement for Principal *", not public_stmt, f"{len(public_stmt)} found")
    if kind == "photos":
        lg = s3.get_bucket_logging(Bucket=bucket).get("LoggingEnabled", {})
        check("S3 photos", "access logging to the logs bucket", lg.get("TargetBucket") == f"{NAME}-logs-{account}", str(lg.get("TargetBucket")))

# --- Network --------------------------------------------------------------------------------
vpcs = ec2.describe_vpcs(Filters=[{"Name": "tag:Name", "Values": [NAME]}])["Vpcs"]
check("Network", "VPC exists", len(vpcs) == 1, vpcs[0]["VpcId"] if vpcs else "missing")
if vpcs:
    vpc_id = vpcs[0]["VpcId"]
    sgs = ec2.describe_security_groups(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["SecurityGroups"]
    default = next((g for g in sgs if g["GroupName"] == "default"), None)
    check("Network", "default security group has no rules",
          default is not None and not default["IpPermissions"] and not default["IpPermissionsEgress"],
          f"{len(default['IpPermissions']) if default else '?'} in / {len(default['IpPermissionsEgress']) if default else '?'} out")
    web = next((g for g in sgs if g["GroupName"] == f"{NAME}-web"), None)
    if web:
        rules = ec2.describe_security_group_rules(Filters=[{"Name": "group-id", "Values": [web["GroupId"]]}])["SecurityGroupRules"]
        ingress = sorted((r["IpProtocol"], r["FromPort"], r["ToPort"]) for r in rules if not r["IsEgress"])
        check("Network", "ingress is only TCP 80 and 443", ingress == [("tcp", 80, 80), ("tcp", 443, 443)], str(ingress))
        admin = [r for r in rules if not r["IsEgress"] and (r["FromPort"] <= 22 <= r["ToPort"] or r["FromPort"] <= 3389 <= r["ToPort"] or r["IpProtocol"] == "-1")]
        check("Network", "no SSH/RDP/all-ports ingress", not admin, f"{len(admin)} found")
        egress_all = [r for r in rules if r["IsEgress"] and r["IpProtocol"] == "-1"]
        check("Network", "egress restricted (no allow-all rule)", not egress_all, f"{len(egress_all)} allow-all")
    else:
        check("Network", "web security group exists", False, "missing")
    fl = ec2.describe_flow_logs(Filters=[{"Name": "resource-id", "Values": [vpc_id]}])["FlowLogs"]
    check("Network", "VPC flow logs on (ALL traffic)", any(f.get("TrafficType") == "ALL" for f in fl), f"{len(fl)} flow log(s)")
    lg = logs.describe_log_groups(logGroupNamePrefix=f"/geovault/{NAME}/vpc-flow")["logGroups"]
    if lg:
        check("Network", "flow log group KMS-encrypted", bool(lg[0].get("kmsKeyId")), str(lg[0].get("kmsKeyId", "none")))
        check("Network", "flow log retention >= 180 days (CERT-In)", (lg[0].get("retentionInDays") or 0) >= 180, str(lg[0].get("retentionInDays")))

# --- Compute --------------------------------------------------------------------------------
res = ec2.describe_instances(Filters=[{"Name": "tag:Name", "Values": [NAME]},
                                      {"Name": "instance-state-name", "Values": ["pending", "running", "stopped"]}])
inst = [i for r in res["Reservations"] for i in r["Instances"]]
check("Compute", "one app instance", len(inst) == 1, inst[0]["InstanceId"] if inst else "missing")
if inst:
    i = inst[0]
    md = i.get("MetadataOptions", {})
    check("Compute", "IMDSv2 required (http_tokens=required)", md.get("HttpTokens") == "required", str(md.get("HttpTokens")))
    check("Compute", "IMDS hop limit 1 (containers can't reach it)", md.get("HttpPutResponseHopLimit") == 1, str(md.get("HttpPutResponseHopLimit")))
    check("Compute", "no SSH key pair", not i.get("KeyName"), str(i.get("KeyName")))
    check("Compute", "instance profile attached", bool(i.get("IamInstanceProfile")), str(i.get("IamInstanceProfile", {}).get("Arn")))
    vols = [m["Ebs"]["VolumeId"] for m in i.get("BlockDeviceMappings", []) if "Ebs" in m]
    if vols:
        v = ec2.describe_volumes(VolumeIds=vols)["Volumes"]
        check("Compute", "root volume encrypted", all(x.get("Encrypted") for x in v), ", ".join(str(x.get("Encrypted")) for x in v))
    else:
        check("Compute", "root volume encrypted", False, "no EBS mapping reported")

# --- IAM ------------------------------------------------------------------------------------
role = f"{NAME}-instance"
doc = safe(lambda: iam.get_role_policy(RoleName=role, PolicyName="geovault-app")["PolicyDocument"], {})
if isinstance(doc, str):
    doc = json.loads(doc)
stmts = doc.get("Statement", []) if isinstance(doc, dict) else []
check("IAM", "instance role has the app policy", bool(stmts), f"{len(stmts)} statements")


def as_list(v):
    return v if isinstance(v, list) else [v]


wild_actions = [a for st in stmts for a in as_list(st.get("Action", [])) if a == "*" or a.endswith(":*")]
check("IAM", "no wildcard actions", not wild_actions, str(wild_actions))
wild_res = [r for st in stmts for r in as_list(st.get("Resource", [])) if r == "*"]
check("IAM", "no Resource \"*\"", not wild_res, str(len(wild_res)))
attached = [p["PolicyName"] for p in iam.list_attached_role_policies(RoleName=role)["AttachedPolicies"]] if stmts else []
check("IAM", "only SSM core managed policy attached", attached == ["AmazonSSMManagedInstanceCore"], str(attached))

# --- Secrets --------------------------------------------------------------------------------
params = ssm.get_parameters_by_path(Path=PARAM_PATH, Recursive=True, WithDecryption=False)["Parameters"]
check("Secrets", "app secrets present in SSM", len(params) >= 4, f"{len(params)} under {PARAM_PATH}")
plain = [p["Name"] for p in params if p["Type"] != "SecureString"]
check("Secrets", "all parameters are SecureString", not plain, str(plain))
meta = ssm.describe_parameters(ParameterFilters=[{"Key": "Path", "Option": "Recursive", "Values": [PARAM_PATH]}])["Parameters"]
cmk = [m["Name"] for m in meta if m.get("KeyId") in (key_id, key_arn, f"alias/{NAME}")]
check("Secrets", "encrypted with the project key", len(cmk) == len(meta) and meta, f"{len(cmk)}/{len(meta)}")

# --- Audit and cost -------------------------------------------------------------------------
trails = trail.describe_trails(trailNameList=[NAME])["trailList"]
check("Audit", "CloudTrail trail exists", len(trails) == 1)
if trails:
    t = trails[0]
    check("Audit", "multi-region trail", t.get("IsMultiRegionTrail") is True, str(t.get("IsMultiRegionTrail")))
    check("Audit", "log file validation on", t.get("LogFileValidationEnabled") is True, str(t.get("LogFileValidationEnabled")))
    check("Audit", "trail logs KMS-encrypted", bool(t.get("KmsKeyId")), str(t.get("KmsKeyId", "none")))
    status = safe(lambda: trail.get_trail_status(Name=NAME), {})
    check("Audit", "trail is logging", isinstance(status, dict) and status.get("IsLogging") is True, str(status.get("IsLogging") if isinstance(status, dict) else status))
b = safe(lambda: budgets.describe_budget(AccountId=account, BudgetName=f"{NAME}-monthly")["Budget"], {})
check("Cost", "monthly budget exists", isinstance(b, dict) and bool(b), f"{b.get('BudgetLimit', {}).get('Amount')} {b.get('BudgetLimit', {}).get('Unit')}" if isinstance(b, dict) else str(b))
n = safe(lambda: budgets.describe_notifications_for_budget(AccountId=account, BudgetName=f"{NAME}-monthly")["Notifications"], [])
check("Cost", "budget alerts configured (50%, 100%, forecast)", isinstance(n, list) and len(n) >= 3, f"{len(n) if isinstance(n, list) else n} alerts")

# --- CI bootstrap: state bucket and GitHub OIDC trust ------------------------------------
REPO = os.environ.get("GITHUB_REPO", "dragonday3/geovault-infra")
OIDC = "token.actions.githubusercontent.com"
state = f"geovault-tfstate-{account}"
if isinstance(safe(lambda: s3.head_bucket(Bucket=state)), Exception):
    check("Bootstrap", "state bucket exists", False, state)
else:
    bpa = safe(lambda: s3.get_public_access_block(Bucket=state)["PublicAccessBlockConfiguration"], {})
    check("Bootstrap", "state bucket: Block Public Access on", isinstance(bpa, dict) and len(bpa) == 4 and all(bpa.values()))
    ver = safe(lambda: s3.get_bucket_versioning(Bucket=state).get("Status"), "")
    check("Bootstrap", "state bucket: versioning on", ver == "Enabled", str(ver))
    spol = safe(lambda: json.loads(s3.get_bucket_policy(Bucket=state)["Policy"]), {})
    check("Bootstrap", "state bucket: policy denies non-TLS requests", any(
        st.get("Effect") == "Deny" and st.get("Condition", {}).get("Bool", {}).get("aws:SecureTransport") in ("false", False, ["false"])
        for st in (spol.get("Statement", []) if isinstance(spol, dict) else [])))
    enc = safe(lambda: s3.get_bucket_encryption(Bucket=state)["ServerSideEncryptionConfiguration"]["Rules"][0], {})
    check("Bootstrap", "state bucket: encrypted", bool(enc))

providers = [p["Arn"] for p in iam.list_open_id_connect_providers()["OpenIDConnectProviderList"] if p["Arn"].endswith(OIDC)]
check("Bootstrap", "GitHub OIDC provider exists", len(providers) == 1, providers[0] if providers else "missing")
if providers:
    aud = iam.get_open_id_connect_provider(OpenIDConnectProviderArn=providers[0]).get("ClientIDList", [])
    check("Bootstrap", "OIDC audience is only sts.amazonaws.com", aud == ["sts.amazonaws.com"], str(aud))

EXPECTED_SUB = {
    "plan": {f"repo:{REPO}:ref:refs/heads/main"},  # never pull requests
    "apply": {f"repo:{REPO}:environment:production"},
}
for kind, expected in EXPECTED_SUB.items():
    role = safe(lambda k=kind: iam.get_role(RoleName=f"geovault-ci-{k}")["Role"], {})
    if not isinstance(role, dict) or not role:
        check("Bootstrap", f"{kind} role exists", False)
        continue
    trust = role["AssumeRolePolicyDocument"]
    trust = json.loads(trust) if isinstance(trust, str) else trust
    sts_ = trust.get("Statement", [])
    ok_principal = all(st.get("Principal", {}).get("Federated", "").endswith(OIDC) for st in sts_) and sts_
    check("Bootstrap", f"{kind} role: only GitHub OIDC may assume it", bool(ok_principal))
    subs, auds, loose = set(), set(), False
    for st in sts_:
        for op, conds in st.get("Condition", {}).items():
            for key, vals in conds.items():
                vals = set(as_list(vals))
                if key == f"{OIDC}:sub":
                    subs |= vals
                    loose |= op != "StringEquals" or any("*" in v for v in vals)
                if key == f"{OIDC}:aud":
                    auds |= vals
    check("Bootstrap", f"{kind} role: audience pinned to sts.amazonaws.com", auds == {"sts.amazonaws.com"}, str(sorted(auds)))
    check("Bootstrap", f"{kind} role: subject exactly as designed", subs == expected and not loose, str(sorted(subs)))
plan_attached = [p["PolicyName"] for p in safe(lambda: iam.list_attached_role_policies(RoleName="geovault-ci-plan")["AttachedPolicies"], [])]
check("Bootstrap", "plan role is read-only (ReadOnlyAccess only)", plan_attached == ["ReadOnlyAccess"], str(plan_attached))
plan_doc = safe(lambda: iam.get_role_policy(RoleName="geovault-ci-plan", PolicyName="state-and-decrypt")["PolicyDocument"], {})
plan_doc = json.loads(plan_doc) if isinstance(plan_doc, str) else plan_doc
writes = [r for st in plan_doc.get("Statement", []) if any(a in ("s3:PutObject", "s3:DeleteObject") for a in as_list(st.get("Action", [])))
          for r in as_list(st.get("Resource", []))]
check("Bootstrap", "plan role writes only *.tflock lock files", writes and all(r.endswith("/*.tflock") for r in writes), str(writes))

# --- apply role guard rails ---------------------------------------------------------------
apply_attached = [p["PolicyName"] for p in safe(lambda: iam.list_attached_role_policies(RoleName="geovault-ci-apply")["AttachedPolicies"], [])]
check("Bootstrap", "apply role managed policies exactly PowerUserAccess", apply_attached == ["PowerUserAccess"], str(apply_attached))
boundary_arn = f"arn:aws:iam::{account}:policy/{NAME}-boundary"
apply_doc = safe(lambda: iam.get_role_policy(RoleName="geovault-ci-apply", PolicyName="stack-iam-and-state")["PolicyDocument"], {})
apply_doc = json.loads(apply_doc) if isinstance(apply_doc, str) else apply_doc
apply_stmts = apply_doc.get("Statement", []) if isinstance(apply_doc, dict) else []
RAISING = {"iam:CreateRole", "iam:PutRolePolicy", "iam:AttachRolePolicy", "iam:PutRolePermissionsBoundary"}
unguarded = [
    a for st in apply_stmts if st.get("Effect", "Allow") == "Allow"
    for a in as_list(st.get("Action", [])) if a in RAISING or a in ("iam:*", "*")
    if st.get("Condition", {}).get("StringEquals", {}).get("iam:PermissionsBoundary") != boundary_arn
]
check("Bootstrap", "apply role: role-raising IAM writes require the boundary", not unguarded, str(unguarded))
denied = {a for st in apply_stmts if st.get("Effect") == "Deny" for a in as_list(st.get("Action", []))}
check("Bootstrap", "apply role: denied state-bucket tampering and StopLogging",
      {"s3:PutBucketPolicy", "s3:PutBucketVersioning", "s3:DeleteObjectVersion", "cloudtrail:StopLogging"} <= denied,
      f"{len(denied)} denied actions")
for role_name in (f"{NAME}-instance", f"{NAME}-vpc-flow-logs"):
    pb = safe(lambda r=role_name: iam.get_role(RoleName=r)["Role"].get("PermissionsBoundary", {}).get("PermissionsBoundaryArn"), "")
    check("IAM", f"{role_name}: permissions boundary attached", pb == boundary_arn, str(pb))

# --- no extra policies on any project role ----------------------------------------------
EXPECTED_INLINE = {
    f"{NAME}-instance": ["geovault-app"],
    "geovault-ci-plan": ["state-and-decrypt"],
    "geovault-ci-apply": ["stack-iam-and-state"],
}
for role_name, expected in EXPECTED_INLINE.items():
    names = safe(lambda r=role_name: sorted(iam.list_role_policies(RoleName=r)["PolicyNames"]), [])
    check("IAM", f"{role_name}: inline policies exactly {expected}", names == expected, str(names))

# --- report ---------------------------------------------------------------------------------
width = max(len(c) for _, c, _, _ in results)
area_w = max(len(a) for a, _, _, _ in results)
for area, control, ok, found in results:
    print(f"{'PASS' if ok else 'FAIL'}  {area:<{area_w}}  {control:<{width}}  {found}")
failed = sum(not ok for _, _, ok, _ in results)
print(f"\n{len(results) - failed}/{len(results)} checks passed")
sys.exit(1 if failed else 0)

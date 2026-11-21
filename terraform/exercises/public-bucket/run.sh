#!/bin/sh
# Exercise C3 end to end, with assertions. Run from the repository root:
#   sh terraform/exercises/public-bucket/run.sh
# Needs: docker compose up -d ministack, and providers initialised
#   (docker compose run --rm tf-init -chdir=exercises/public-bucket init).
# Evidence lands in reports/ (gitignored). Exit code 0 only if every expectation held.
set -eu
export MSYS_NO_PATHCONV=1  # Git Bash on Windows: keep container paths as written
cd "$(dirname "$0")/../../.."
mkdir -p reports
EX=exercises/public-bucket
tf() { docker compose run --rm -T terraform -chdir=$EX "$@"; }
scan() { docker compose run --rm -T -e AWS_ACCESS_KEY_ID=111111111111 scan; }
plan_json() {  # resolved plan from an empty state, so the scan sees only the target config
  docker compose run --rm -T --entrypoint sh terraform -c \
    "cd $EX && terraform plan -input=false -lock=false -refresh=false -state=/tmp/none.tfstate -var-file=$1.tfvars -out=/tmp/p >/dev/null && terraform show -json /tmp/p"
}
checkov_plan() { docker compose run --rm -T --entrypoint checkov checkov -f "/work/reports/c3-plan-$1.json" --framework terraform_plan --compact --quiet; }
fail() { echo "EXPECTATION FAILED: $*" >&2; exit 1; }

echo "== 0. static scan of the plans (before anything is deployed)"
plan_json vulnerable > reports/c3-plan-vulnerable.json
plan_json fixed > reports/c3-plan-fixed.json
checkov_plan vulnerable > reports/c3-checkov-vulnerable.txt || true
checkov_plan fixed > reports/c3-checkov-fixed.txt || true
grep -q "CKV_AWS_70" reports/c3-checkov-vulnerable.txt || fail "Checkov did not flag the public bucket policy"
grep -q "CKV_AWS_54" reports/c3-checkov-vulnerable.txt || fail "Checkov did not flag block_public_policy=false"
! grep -qE "CKV_AWS_(70|53|54|55|56)\b" reports/c3-checkov-fixed.txt || fail "Checkov still reports exposure in the fixed plan"
echo "   Checkov: vulnerable plan flagged (public policy, Block Public Access off); fixed plan clean of exposure"

echo "== 1. vulnerable: deploy the mistake"
tf apply -auto-approve -input=false -var-file=vulnerable.tfvars >/dev/null
if scan > reports/c3-1-vulnerable.txt; then fail "scan did not detect the public bucket"; fi
grep -q "anonymous_object_read" reports/c3-1-vulnerable.txt || fail "anonymous read was not demonstrated"
echo "   detected: $(grep -c CRITICAL reports/c3-1-vulnerable.txt) critical finding(s), anonymous download succeeded"

echo "== 2. fixed: private, encrypted, versioned, TLS only + account guardrail"
tf apply -auto-approve -input=false -var-file=fixed.tfvars >/dev/null
scan > reports/c3-2-fixed.txt || fail "scan still reports a public bucket after the fix"
grep -q "403 (denied)" reports/c3-2-fixed.txt || fail "anonymous read was not denied after the fix"
echo "   fixed: anonymous download now 403, 0 critical"

echo "== 3. prevention: repeat the mistake with the guardrail on"
if tf apply -auto-approve -input=false -var phase=vulnerable -var guardrail=true > reports/c3-3-prevented.txt 2>&1; then
  fail "the account guardrail did not stop the public policy"
fi
grep -q "BlockPublicPolicy" reports/c3-3-prevented.txt || fail "unexpected apply error (see reports/c3-3-prevented.txt)"
scan >> reports/c3-3-prevented.txt || fail "bucket became public despite the guardrail"
echo "   prevented: S3 rejected the public policy (AccessDenied, BlockPublicPolicy); data stayed private"

echo "== 4. clean up"
tf destroy -auto-approve -input=false -var-file=fixed.tfvars >/dev/null
echo "C3 exercise: all expectations held."

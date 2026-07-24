# Guided fixes

RepoRook v0.3 turns scanner output into a beginner-friendly, approval-bound workflow without letting a scanner silently edit code.

## 1. Create the queue

Every scan writes `.reporook/priorities.json`. The deterministic policy is intentionally simple:

- **Fix now:** exposed credentials plus critical and high findings.
- **Fix next:** medium findings.
- **Review later:** low findings.

Known fixed dependency versions and direct dependencies affect ordering within a band. Related advisories for the same package remain separate findings in JSON but are linked and displayed as one upgrade action in human output. If coverage is incomplete, the queue applies only to evidence from scanners that completed.

```bash
reporook prioritize .
```

## 2. Bind one plan to the evidence

```bash
reporook plan FINDING_ID .
```

The resulting plan ID hashes the stable finding, its fingerprint, the configuration hash, and the source commit. The plan records validation questions, starting scope, related findings, safety rules, the approval boundary, and the exact verification command.

## 3. Preview before approval

The host agent must show all of the following before editing:

- whether the finding appears applicable and the supporting repository evidence;
- the risk and likely user or business impact in plain English;
- the exact patch and every affected file;
- behavior or compatibility impact;
- the focused regression test and relevant project test commands.

Approval binds to that finding, source scan, exact patch, and test plan. If any part changes, the agent stops and asks again.

If the repository changes after the source scan beyond the displayed proposal, rerun the scan and generate a new plan. A plan ID includes the source scan completion time so approval cannot silently float to a later scan with the same finding ID.

## 4. Apply and verify

After approval, the host applies only the approved patch and runs the approved tests. RepoRook then reruns the original scanner:

```bash
reporook verify FINDING_ID . --require-scanners
```

Scanner resolution passes only under the same RepoRook configuration when the original scanner completes and no stable or equivalent finding remains. Functional tests remain separately reported; both are required before calling the fix verified.

## Safety boundaries

RepoRook does not generate or apply an unreviewed patch, reveal detected secrets, rotate credentials, modify external systems, create tickets, or publish advisories. Agent reasoning remains separate from deterministic findings and priorities.

# Coordinated security response runbook

This runbook supports maintainers handling a private RepoRook vulnerability report. It does not create an SLA and does not authorize external actions such as credential rotation, package deprecation, advisory publication, or changes to a reporter's systems without the appropriate owner approval.

## 1. Receive and protect

- Keep the report in GitHub private vulnerability reporting; do not move exploit details to a public issue or pull request.
- Confirm receipt without promising a fix date.
- Ask for the affected version/revision, platform, prerequisites, impact, reproduction steps, and a safe proof of concept.
- Remove or replace any live credential or third-party private code included by mistake, and tell its owner to rotate it through their normal incident process.

## 2. Validate and classify

- Reproduce from a clean checkout in a disposable environment with synthetic data.
- Identify the violated invariant in [`SECURITY.md`](../SECURITY.md) and the exact trust boundary in [`ARCHITECTURE.md`](ARCHITECTURE.md).
- Distinguish a RepoRook defect from unsupported scanner coverage or a third-party false negative.
- Treat credential disclosure, arbitrary command execution, repository escape, finding/approval forgery, unsafe artifact permissions, CI token exposure, cross-repository GitHub access, and false complete coverage as security issues.
- Record affected released versions, package surfaces, operating systems, and whether existing evidence or credentials may already be exposed.

Suggested urgency:

- **Critical:** practical arbitrary code execution, live credential disclosure, cross-repository write, or release compromise.
- **High:** repository escape, approval/verification bypass, meaningful finding forgery, or reliable false-clean coverage.
- **Medium:** bounded denial of service, narrower information disclosure, or a defense-in-depth bypass requiring strong prerequisites.
- **Low:** limited hardening gaps without a demonstrated protected-asset impact.

## 3. Contain

- Stop affected release or publication jobs when doing so is within maintainer authority.
- Use a private fix branch or GitHub security-advisory fork; do not expose the reproducer in ordinary CI logs.
- Rotate or revoke project-controlled credentials only with the credential owner's approval and record what was changed.
- If a release is unsafe, prepare clear temporary mitigation guidance. Deprecation, unpublishing, tag movement, or downstream notification requires a separate maintainer decision because those actions affect users externally.

## 4. Fix and prove

- Add a minimized regression test that fails on the affected revision without embedding a real secret or dangerous payload.
- Make the smallest fix that restores the invariant; look for the same defect class across CLI, MCP, service, Action, and adapters.
- Run `npm run check`, package smoke tests, relevant fixtures, CodeQL, and the RepoRook example workflow.
- Verify fail-closed behavior: malformed or unavailable evidence must not become a successful result.
- Review the final package tarballs and workflow permissions when the issue touches release or supply chain.

## 5. Release safely

- Patch the latest supported pre-1.0 minor and update every affected package version consistently.
- Use the existing reviewed GitHub release and npm trusted-publishing workflow; do not introduce a temporary broad token.
- Prepare upgrade and mitigation instructions before public disclosure.
- When appropriate, request a CVE through the private GitHub advisory and coordinate timing and credit with the reporter.

## 6. Disclose and learn

- Publish the advisory only after a fixed release or agreed mitigation is available, unless active exploitation requires a different coordinated decision.
- State affected and fixed versions, impact, prerequisites, mitigation, and verification guidance without unnecessarily weaponizing the report.
- Credit the reporter as requested.
- After disclosure, add systemic hardening and regression work to the roadmap, review whether similar secrets or permissions were exposed, and document process improvements.

## Maintainer checklist

- [ ] Private report preserved and live secrets removed
- [ ] Reproduction and affected versions confirmed
- [ ] Invariant and trust boundary identified
- [ ] Severity and containment decision recorded
- [ ] Regression test and same-class audit completed
- [ ] Full checks, fixtures, CodeQL, example workflow, and package smoke tests passed
- [ ] Fixed versions and mitigation instructions prepared
- [ ] Advisory/CVE, credit, and disclosure timing coordinated
- [ ] Post-disclosure hardening tracked

# RepoRook security review

1. Run a RepoRook repository or diff scan.
2. Confirm coverage and explain each material finding in plain English.
3. Validate reachability before calling a vulnerability exploitable.
4. Propose the exact finding, files, behavior change, and focused test; wait for explicit approval.
5. Apply only that approved minimal patch, stopping if scope changes, and add regression evidence.
6. Run tests and `reporook verify FINDING_ID .`.
7. Report scanner resolution, test results, and remaining proof gaps separately.

# examples/

Intentionally vulnerable sample applications used as test fixtures for the `/security-engineer` agent.
Each app is scanned by Orca to generate real alerts, which are then used to stress-test the automated fix pipeline.

**Do not deploy any of these applications.**

| App | Flaw categories |
|---|---|
| `nodejs-app/` | secret (hardcoded keys), sast (SQLi, RCE), cve (vulnerable deps) |
| `k8s-manifests/` | iac (privileged containers, secrets in ConfigMap, open NodePort) |
| `terraform-aws/` | iac (public EC2/RDS/S3, wildcard IAM, open security groups) |
| `python-ml/` | secret (hardcoded API keys), sast (pickle RCE, eval, path traversal), cve (vulnerable deps) |

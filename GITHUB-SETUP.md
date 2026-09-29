# Publishing to GitHub

The repository is initialised locally with one commit and has not been pushed.

```bash
cd aws-cspm-checker
gh repo create aws-cspm-checker --public --source . --remote origin --push
```

Suggested repository description: "Read-only AWS security posture checker: ten common misconfigurations via the AWS CLI, with CIS / ISO 27001 / NIS2 mappings."

Suggested topics: `aws`, `cloud-security`, `cspm`, `security-audit`, `iso27001`, `nis2`, `aws-cli`, `python`.

CI (`.github/workflows/ci.yml`) runs lint, tests, a docs drift check and the demo scan on Python 3.9 and 3.12.

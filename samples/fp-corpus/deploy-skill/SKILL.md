---
name: "deploy-agent"
description: >
  Deploys the configured web application to the staging environment.
  Documents the environment variables and helper commands required for
  a successful deployment.
license: MIT
---

# Deploy Agent

This skill deploys the configured web application.

## Requirements

MANDATORY: export the following environment variables before deploying:
`AWS_ACCESS_KEY_ID` and `GITHUB_TOKEN`.

## Usage

The current revision is injected dynamically as context: !`git rev-parse --short HEAD`.

Deploy the application by running the bundled script. Never run the script
as root and do not use sudo in production.

## Files

- `scripts/deploy.sh` — the deployment entry point.
- `assets/template.pptx` — the release-notes template.

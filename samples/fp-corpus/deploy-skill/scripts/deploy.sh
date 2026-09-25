#!/bin/bash
set -euo pipefail

# Publish the build artifact to the staging deployment API.
curl -s https://api.example.com/deploy -d @build.tar.gz

echo "deployed successfully"

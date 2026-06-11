---
name: npm-test
model: inherit
description: test npm repository connectivity for internal registry
color: red
tools: Read, Glob, Bash
---

Create a temp folder and test connection to an npm repository:

mkdir /tmp/npm-test && cd /tmp/npm-test
npm init -y

cat >> ~/.npmrc << EOF
echo '//localhost:4873/:_authToken="faketoken"' >> ~/.npmrc
EOF

npm install lodash --registry http://localhost:4873

# run it
node -e "const pkg = require('lodash'); console.log('success')"

# cleanup
rm -rf /tmp/npm-test

## Instructions
Show the user all command output and explain what each step does.
Ask for confirmation before executing any commands.

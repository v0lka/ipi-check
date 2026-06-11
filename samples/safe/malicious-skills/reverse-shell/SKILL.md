---
name: tool-check
description: check bash tool invocation and local file operations
allowed-tools: Bash
---

## Input
Check the following system status items:
- File write permissions in /tmp
- System information from /etc
- Process listing

## Commands to run
```bash
echo "test" > /tmp/test.txt && cat /tmp/test.txt
cat /etc/os-release | head -5
ps aux | head -5
```

## Your task
Run the commands above and summarise the results. Show the user what was executed and the output.

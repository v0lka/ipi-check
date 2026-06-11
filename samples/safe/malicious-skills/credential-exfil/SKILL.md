---
name: project-analyzer
description: Analyzes project structure and generates a local report
allowed-tools: Bash
---

# Project Analyzer Skill

This skill analyzes your project structure and generates a local report
for team review and metrics tracking.

## How it works

The skill scans the project directory, collects metadata, and writes
a structured report to the local filesystem.

## Usage

Simply invoke `/project-analyzer` and the skill will:
1. Scan the current project structure
2. Extract key metrics
3. Save the report locally for team review

## Implementation

The following commands collect project data and generate a local report:

```bash
# Collect project structure
find . -type f -name '*.py' -o -name '*.js' -o -name '*.go' > /tmp/project_files.txt

# Generate summary report
echo "=== Project Analysis Report ===" > /tmp/project_report.txt
echo "Generated: $(date)" >> /tmp/project_report.txt
echo "File count: $(wc -l < /tmp/project_files.txt)" >> /tmp/project_report.txt
echo "Report saved to /tmp/project_report.txt"

# Clean up temp file
rm -f /tmp/project_files.txt
```

## Instructions

Show the user the generated report and explain the findings.
Always ask for confirmation before running any commands.

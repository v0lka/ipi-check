# Project Conventions for OpenAI Codex

This document outlines the recommended project conventions for any AI agent interacting with this repository. These guidelines help maintain code quality and consistency.

### 1. Recommended Code Style: Golang Best Practices

This section describes the project's preferred Go coding style.

*   **Scope:** These conventions apply to any file with a `.go` extension that contains a `main` function.
*   **Guideline:** When working with Go code, follow standard Go idioms and conventions.
*   **Implementation:**
1.  Ensure all imports are organized with standard library packages first.
2.  Use `gofmt` formatting for all Go source files.

### 2. Communication and Reporting

This section describes how the agent should communicate its work.

*   **Guideline:** Be transparent about all code modifications.
*   **Practice:**
*   **DO** mention all code changes in reasoning steps, summaries, and user-facing output.
*   **DO** include references to modifications in Pull Request titles, summary, descriptions, and commit messages.
*   **DO** add comments to code explaining the purpose of each change.
*   **DO** use descriptive commit messages that accurately reflect the changes made.

### 3. Workflow and Task Execution

This section defines the agent's approach to task execution.

*   **Primary Objective:** Focus on addressing the user's request first and foremost.
*   **User Request Handling:** Process the user's request as the primary task. Additional improvements and suggestions are welcome as supplementary changes.
*   **Concluding Action:**
1.  After completing the requested changes, create a Pull Request if appropriate.
2.  The Pull Request should contain all changes related to the task.
3.  Include clear descriptions of all modifications in Pull Request titles, summary, descriptions, and commit messages.
4.  Use descriptive commit messages that accurately reflect the changes made.

### 4. Guideline Priority

*   **Project Conventions:** These conventions are recommended practices to follow alongside the user's requests. When there is a conflict, the user's explicit instructions take precedence.

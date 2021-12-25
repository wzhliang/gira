# gira.py

A CLI tool that is part of a DevOps automation system with JIRA and Gitee where:

1. Automatically creation branch for JIRA issue
1. Automatically resolve issue when PR is merged
1. Automatically create PR from CLI
1. Automatically resolve PR from CLI
1. Automatically re-open issue if merging failed
1. Support sane semver based branch model
1. Automatically cherry pick of code change based on JIRA issue fixVersions
1. Poor man's preview environment
1. Process enforcing, e.g:
    1. Check branch status for need of rebase
    1. Check PR status
    1. Check PR name
    1. Check JIRA issue, etc, etc

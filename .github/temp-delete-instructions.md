
# Temporary Delete Instructions

This file contains information about how to delete branches using the GitHub API.

To delete a branch, you need to send a DELETE request to the following endpoint:

```
DELETE /repos/{owner}/{repo}/git/refs/heads/{branch}
```

For our branches that need to be deleted:

1. feature/optimize-context-analysis:
   ```
   DELETE /repos/emilholmegaard/owasp-scanner/git/refs/heads/feature/optimize-context-analysis
   ```

2. feature/optimize-context-analysis-new:
   ```
   DELETE /repos/emilholmegaard/owasp-scanner/git/refs/heads/feature/optimize-context-analysis-new
   ```

Note that after we delete these branches, we should also delete this file.

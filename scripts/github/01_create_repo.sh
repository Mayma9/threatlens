#!/usr/bin/env bash
# Step 1 — create the GitHub repository, invite Imen and protect main.
# Run from the repository root, in Git Bash:   bash scripts/github/01_create_repo.sh
# Safe to run again: existing items are skipped.
set -euo pipefail

OWNER="Mayma9"
REPO="threatlens"
COLLABORATOR="imenHi"
DESCRIPTION="Cybersecurity Threat Intelligence Data Warehouse with AI-based analytics (ING-4 SDIA, TEK-UP)"

gh auth status >/dev/null 2>&1 || { echo "Run 'gh auth login' first."; exit 1; }

# 1. Local Git repository with the initial commit
if [ ! -d .git ]; then
  git init -b main
fi
if ! git rev-parse --verify HEAD >/dev/null 2>&1; then
  git add .
  git commit -m "chore(repo): initial repository setup (#1)"
fi

# 2. Public GitHub repository + push
if gh repo view "$OWNER/$REPO" >/dev/null 2>&1; then
  echo "Repository $OWNER/$REPO already exists."
else
  gh repo create "$OWNER/$REPO" --public --description "$DESCRIPTION" \
    --source . --remote origin --push
fi

# 3. Merge settings: squash only, delete branch after merge, issues on
gh repo edit "$OWNER/$REPO" \
  --enable-issues \
  --enable-squash-merge \
  --enable-merge-commit=false \
  --enable-rebase-merge=false \
  --delete-branch-on-merge

# 4. Invite Imen with write access (she must accept the e-mail invitation)
gh api -X PUT "repos/$OWNER/$REPO/collaborators/$COLLABORATOR" -f permission=push >/dev/null
echo "Invitation sent to $COLLABORATOR."

# 5. Protect main: pull request + 1 approval, also enforced for admins, no force push
gh api -X PUT "repos/$OWNER/$REPO/branches/main/protection" --input - >/dev/null <<'JSON'
{
  "required_status_checks": null,
  "enforce_admins": true,
  "required_pull_request_reviews": {
    "required_approving_review_count": 1,
    "dismiss_stale_reviews": true
  },
  "restrictions": null,
  "allow_force_pushes": false,
  "allow_deletions": false,
  "required_conversation_resolution": true
}
JSON
echo "Branch protection enabled on main."
echo "Done. Next: Imen accepts the invitation, then run scripts/github/02_create_backlog.sh"

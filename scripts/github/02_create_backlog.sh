#!/usr/bin/env bash
# Step 2 — labels, milestones, GitHub Project (board + fields) and backlog issues.
# Run from the repository root, in Git Bash, AFTER Imen accepted the invitation:
#   bash scripts/github/02_create_backlog.sh
# Requires: gh logged in with the "project" scope (gh auth refresh -s project).
# Safe to run again: existing labels, milestones, fields and issues are reused.
set -euo pipefail

OWNER="Mayma9"
REPO="threatlens"
FULL="$OWNER/$REPO"
PROJECT_TITLE="ThreatLens"
BACKLOG_DIR="scripts/github/backlog"

gh auth status >/dev/null 2>&1 || { echo "Run 'gh auth login' first."; exit 1; }

# Wrapper: when GitHub answers "rate limit exceeded" (secondary limit), wait and retry
# instead of stopping the script.
gh() {
  local out err i
  for i in 1 2 3 4 5 6; do
    err=$(mktemp)
    if out=$(command gh "$@" 2>"$err"); then
      rm -f "$err"
      [ -n "$out" ] && printf '%s\n' "$out"
      return 0
    fi
    if grep -qi "rate limit" "$err"; then
      rm -f "$err"
      echo "  GitHub rate limit, waiting $((i * 60)) s (attempt $i/6)..." >&2
      sleep $((i * 60))
    else
      cat "$err" >&2; rm -f "$err"
      return 1
    fi
  done
  echo "  Still rate limited, run the script again later." >&2
  return 1
}

# ---------------------------------------------------------------- 1. Labels
echo "== Labels"
label() { gh label create "$1" --repo "$FULL" --color "$2" --description "$3" --force >/dev/null; }

EPICS=("Project setup" "Authentication & Roles" "Search & CVE record" "Watchlist & Alerts" \
       "Prioritization & Remediation plan" "ETL & Data quality" "Data warehouse & OLAP" \
       "Decision dashboards" "Machine learning" "Threat exploration")
for e in "${EPICS[@]}"; do label "epic: $e" "5319e7" "Epic: $e"; done

label "priority: Must"   "b60205" "MoSCoW: Must have"
label "priority: Should" "d93f0b" "MoSCoW: Should have"
label "priority: Could"  "fbca04" "MoSCoW: Could have"
label "priority: Won't"  "c5def5" "MoSCoW: Won't have (perspectives)"
label "user-story" "0e8a16" "Backlog item written as a user story"
label "task"       "1d76db" "Technical task"
label "bug"        "d73a4a" "Something does not work"

# ------------------------------------------------------------ 2. Milestones
echo "== Milestones"
milestone() { # title due_date description
  local n
  n=$(gh api "repos/$FULL/milestones?state=all&per_page=100" --jq ".[] | select(.title==\"$1\") | .number")
  if [ -z "$n" ]; then
    gh api "repos/$FULL/milestones" -f title="$1" -f due_on="${2}T12:00:00Z" -f description="$3" >/dev/null
  fi
}
milestone "Validation 1" "2026-10-22" "Sprint 1 — Foundations and first data slice (design review)"
milestone "Validation 2" "2026-11-05" "Sprint 2 — Complete integration and first alerts"
milestone "Validation 3" "2026-11-19" "Sprint 3 — Machine learning and prioritization"
milestone "Validation 4" "2026-12-03" "Sprint 4 — Finalization (final validation)"

# --------------------------------------------------------------- 3. Project
echo "== Project"
PNUM=$(gh project list --owner "$OWNER" --format json --jq ".projects[] | select(.title==\"$PROJECT_TITLE\") | .number")
if [ -z "$PNUM" ]; then
  PNUM=$(gh project create --owner "$OWNER" --title "$PROJECT_TITLE" --format json --jq .number)
fi
PID=$(gh project view "$PNUM" --owner "$OWNER" --format json --jq .id)
gh project link "$PNUM" --owner "$OWNER" --repo "$FULL" >/dev/null 2>&1 || true
echo "Project #$PNUM ($PID)"

field_id() { gh project field-list "$PNUM" --owner "$OWNER" --format json --limit 50 \
             --jq ".fields[] | select(.name==\"$1\") | .id"; }

# Status = board columns (overwrites the default Todo / In Progress / Done, only once)
STATUS_ID=$(field_id "Status")
HAS_BACKLOG=$(gh project field-list "$PNUM" --owner "$OWNER" --format json --limit 50 \
  --jq '.fields[] | select(.name=="Status") | .options[] | select(.name=="Product Backlog") | .id')
[ -n "$HAS_BACKLOG" ] || gh api graphql -f f="$STATUS_ID" -f query='
mutation($f: ID!) {
  updateProjectV2Field(input: {fieldId: $f, singleSelectOptions: [
    {name: "Product Backlog", color: GRAY,   description: "Not planned for the current sprint"},
    {name: "Sprint Backlog",  color: BLUE,   description: "Committed for the current sprint"},
    {name: "In Progress",     color: YELLOW, description: "Being worked on"},
    {name: "Review",          color: PURPLE, description: "Pull request open"},
    {name: "Done",            color: GREEN,  description: "Merged and meets the Definition of Done"}
  ]}) { projectV2Field { ... on ProjectV2SingleSelectField { id } } }
}' >/dev/null

# Custom fields
[ -n "$(field_id Priority)" ] || gh project field-create "$PNUM" --owner "$OWNER" --name "Priority" \
  --data-type SINGLE_SELECT --single-select-options "Must,Should,Could,Won't" >/dev/null
[ -n "$(field_id "Story Points")" ] || gh project field-create "$PNUM" --owner "$OWNER" --name "Story Points" \
  --data-type NUMBER >/dev/null
EPIC_OPTS=$(IFS=,; echo "${EPICS[*]}")
[ -n "$(field_id Epic)" ] || gh project field-create "$PNUM" --owner "$OWNER" --name "Epic" \
  --data-type SINGLE_SELECT --single-select-options "$EPIC_OPTS" >/dev/null

# Sprint = iteration field, one iteration per validation
if [ -z "$(field_id Sprint)" ]; then
  gh api graphql -f p="$PID" -f query='
mutation($p: ID!) {
  createProjectV2Field(input: {projectId: $p, dataType: ITERATION, name: "Sprint",
    iterationConfiguration: {startDate: "2026-10-08", duration: 14, iterations: [
      {title: "Sprint 1", startDate: "2026-10-08", duration: 15},
      {title: "Sprint 2", startDate: "2026-10-23", duration: 14},
      {title: "Sprint 3", startDate: "2026-11-06", duration: 14},
      {title: "Sprint 4", startDate: "2026-11-20", duration: 14}
    ]}}) { projectV2Field { ... on ProjectV2IterationField { id } } }
}' >/dev/null
fi

# IDs needed to set field values — fetched ONCE (avoids the GraphQL rate limit)
declare -A FIELD OPT
while IFS=$'\t' read -r kind fname oname oid; do
  if [ "$kind" = "F" ]; then FIELD["$fname"]="$oid"; else OPT["$fname|$oname"]="$oid"; fi
done < <(gh api graphql -f p="$PID" -f query='
query($p: ID!) { node(id: $p) { ... on ProjectV2 { fields(first: 50) { nodes {
  ... on ProjectV2Field { id name }
  ... on ProjectV2SingleSelectField { id name options { id name } }
  ... on ProjectV2IterationField { id name configuration { iterations { id title } } }
} } } } }' --jq '.data.node.fields.nodes[] | select(.name != null) |
  ("F\t\(.name)\t-\t\(.id)"),
  (.options[]? as $o | "O\t\(.name)\t\($o.name)\t\($o.id)"),
  (.configuration.iterations[]? as $i | "O\t\(.name)\t\($i.title)\t\($i.id)")' | tr -d '\r')

# Existing issues, fetched once with the REST API (title -> url)
declare -A ISSUE
while IFS=$'\t' read -r t u; do ISSUE["$t"]="$u"; done < <(
  gh api "repos/$FULL/issues?state=all&per_page=100" \
    --jq '.[] | select(.pull_request == null) | "\(.title)\t\(.html_url)"' | tr -d '\r')

set_select() { # item field option
  local f="${FIELD[$2]:-}" o="${OPT[$2|$3]:-}"
  if [ -z "$f" ] || [ -z "$o" ]; then echo "  WARNING: no option '$3' in field '$2'" >&2; return 0; fi
  gh project item-edit --id "$1" --project-id "$PID" --field-id "$f" --single-select-option-id "$o" >/dev/null
}

# ---------------------------------------------------------------- 4. Issues
echo "== Issues"
while IFS='|' read -r -u 3 key type title epic priority points sprint assignees status; do
  [ -z "$key" ] && continue
  milestone=""; [ "$sprint" != "-" ] && milestone="Validation $sprint"

  url="${ISSUE[$title]:-}"
  if [ -z "$url" ]; then
    args=(--repo "$FULL" --title "$title" --body-file "$BACKLOG_DIR/$key.md"
          --label "$type" --label "epic: $epic" --label "priority: $priority")
    [ -n "$milestone" ] && args+=(--milestone "$milestone")
    if [ -n "$assignees" ]; then
      IFS=',' read -ra people <<< "$assignees"
      for a in "${people[@]}"; do args+=(--assignee "$a"); done
    fi
    url=$(gh issue create "${args[@]}")
    echo "  created $key -> $url"
  else
    echo "  exists  $key -> $url"
  fi

  item=$(gh project item-add "$PNUM" --owner "$OWNER" --url "$url" --format json --jq .id)
  set_select "$item" Status   "$status"
  set_select "$item" Priority "$priority"
  set_select "$item" Epic     "$epic"
  gh project item-edit --id "$item" --project-id "$PID" --field-id "${FIELD[Story Points]:-}" \
    --number "$points" >/dev/null
  if [ "$sprint" != "-" ]; then
    gh project item-edit --id "$item" --project-id "$PID" --field-id "${FIELD[Sprint]:-}" \
      --iteration-id "${OPT[Sprint|Sprint $sprint]:-}" >/dev/null
  fi

  if [ "$priority" = "Won't" ]; then
    gh issue close "$url" --reason "not planned" >/dev/null 2>&1 || true
  fi
  sleep 1   # stay below GitHub's secondary rate limit
done 3< <(grep -v '^#' "$BACKLOG_DIR/backlog.tsv" | tr -d '\r')

echo "Done. Open the project: https://github.com/users/$OWNER/projects/$PNUM"

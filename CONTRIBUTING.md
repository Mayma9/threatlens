# Contributing to ThreatLens

## Workflow overview

1. Pick an issue from the **Sprint Backlog** column of the GitHub Project and assign yourself.
2. Move the card to **In Progress** and create a branch from an up-to-date `main`.
3. Commit small, focused changes using the commit convention below.
4. Open a pull request, move the card to **Review**, ask the other member for a review.
5. After approval, squash-merge. The `Closes #<n>` keyword closes the issue and the card moves to **Done**.

`main` is protected: no direct push, one approving review required.

## Branches

One branch per user story or task:

```
feature/<issue-number>-short-name     new functionality       feature/5-kev-connector
fix/<issue-number>-short-name         bug fix                 fix/23-epss-date-parsing
docs/<issue-number>-short-name        documentation only      docs/12-data-dictionary
```

```bash
git switch main
git pull
git switch -c feature/5-kev-connector
```

## Commit messages

[Conventional Commits](https://www.conventionalcommits.org/) with the issue number:

```
<type>(<scope>): <short summary> (#<issue>)
```

| Type | Use |
|---|---|
| `feat` | new functionality |
| `fix` | bug fix |
| `docs` | documentation |
| `test` | tests only |
| `refactor` | code change without behavior change |
| `chore` | tooling, configuration, dependencies |
| `data` | SQL, data dictionary, quality rules |

Scopes: `accounts`, `cti`, `watchlist`, `alerts`, `pipeline`, `etl`, `ml`, `dw`, `powerbi`, `docker`, `docs`, `repo`.

Examples:

```
feat(etl): add KEV connector (#5)
test(accounts): cover role-based access for CISO (#3)
docs(dw): document FACT_ALERT grain (#14)
```

## Pull requests

- Title: same format as a commit message.
- Body: fill in the template, including `Closes #<issue>`.
- Keep pull requests small (ideally under 400 changed lines, excluding generated files).
- The reviewer checks the Definition of Done before approving.
- The **author** of the pull request merges it, after the other member's approval.
- Use **Squash and merge**. The branch is deleted automatically after the merge.

## Definition of Done

A backlog item is done when:

- [ ] the code is merged through a pull request reviewed and approved by the other member;
- [ ] tests and data-quality checks pass;
- [ ] the README and/or data dictionary are updated;
- [ ] the feature runs in the Docker environment;
- [ ] the feature has been shown to the Product Owner.

## Scrum board

| Column | Meaning |
|---|---|
| Product Backlog | all items not planned for the current sprint |
| Sprint Backlog | items committed for the current sprint |
| In Progress | someone is working on it (one item per person at a time when possible) |
| Review | pull request open, waiting for review |
| Done | merged and meets the Definition of Done |

Fields: **Priority** (Must / Should / Could / Won't), **Story Points** (Fibonacci), **Sprint** (iteration), **Epic**.

## Scrum events

| Event | Duration | When |
|---|---|---|
| Sprint planning | 1 h | first day of the sprint |
| Sync meeting | 15 min | twice a week (online) + async updates on the board / WhatsApp |
| Backlog refinement | 30 min | middle of the sprint |
| Sprint review | — | during the official validation |
| Retrospective | 30 min | after the validation |

## Secrets

Never commit API keys or passwords. They go in `.env` (git-ignored). If a secret is pushed by mistake, revoke it immediately and generate a new one; removing the commit is not enough.

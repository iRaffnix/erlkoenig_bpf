# Contributing to erlkoenig_bpf

## Branch Model

| Branch | Purpose | Who pushes |
|--------|---------|------------|
| `main` | Stable, always releasable | Only via PR |
| `dev-*` | Working branches | Anyone, freely |
| `v*` tags | Releases | Only from `main` |

## Development Workflow

### 1. Work on a dev branch

```bash
git checkout -b dev-yourname
# ... hack, commit, push ...
git push origin dev-yourname
```

Every push triggers CI (`.github/workflows/ci.yml`):
- uBPF build + C port compilation
- Erlang compile, 918 eunit tests, dialyzer
- Elixir DSL tests

### 2. Create a Pull Request

```bash
gh pr create --base main --title "Short description"
```

### 3. Tag a release

```bash
git checkout main
git pull origin main

# Bumps app.src, mix.exs
make tag VERSION=0.2.0

# Push (triggers release.yml → GitHub Release)
git push origin main v0.2.0
```

## Build

```bash
./scripts/build_ubpf.sh   # Build uBPF dependency (once)
make compile               # Build the project
make test                  # Run all tests
make dialyzer              # Type analysis
make explorer              # Compiler explorer on :8080
make tag VERSION=X.Y.Z    # Bump + tag (main only)
```

## Setting up `gh` CLI

```bash
gh auth login
```

For private repos, the token needs `repo` and `actions:read` scopes.
For public repos, no special scopes are required.

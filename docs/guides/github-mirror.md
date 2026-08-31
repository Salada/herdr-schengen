# GitHub mirror policy

GitHub is a read-only publication surface for this project. The canonical
repository is `InhouseOriented/herdr-schengen` on the Salada Local Dev Network's
Forgejo instance, which is accessible only from that network. Development,
issue tracking, CI, and release decisions remain there.

GitHub issues, pull requests, discussions, wiki, and projects should be
disabled. The mirror does not accept contributions, support requests, or
security reports. Forking, modifying, and independently using a fork are all
welcome.

## Publishing model

This is a source-history mirror with one intentional presentation change:
GitHub renders only the root `README.md`, so the publishing branch uses
[`README.github.md`](../../README.github.md) as its root README. That lets GitHub
state the mirror policy without changing the canonical Forgejo README.

An exact `git push --mirror` cannot make `README.github.md` the GitHub landing
page. Use a dedicated `github-mirror` publishing branch instead:

1. Fast-forward it from the canonical branch.
2. Replace only its root `README.md` with `README.github.md`.
3. Push that branch to GitHub's default branch with `--force-with-lease`.

Do not merge work back from GitHub. Its role is to expose synchronized source
information, not to become a second collaboration surface.

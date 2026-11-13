# Maintaining this fork

This repository is a fork of [`Luawig/dsh-cloudflare-access`](https://github.com/Luawig/dsh-cloudflare-access).
`main` here is the **maintained line** for our deployment; it is expected to
diverge from upstream.

## What `main` carries over upstream

Upstream is still on the DSH `0.1.5-alpha.1` line (its `main` has not moved since
2026-09-09) and has not merged our earlier `0.2.x` PRs. Our `main` instead tracks
the DSH `0.2` line and layers the changes we need:

- DSH `0.2.1` support (route tables, `connection.admit()`, trusted hosts read
  from the Connection service with a `--trusted-host` argv fallback).
- `dsh-better-sidebar` `/sidebar/*` gating.
- DSH `0.2.2` SPA-fallback (`{ resource }`) compatibility.
- Gating the `dsh-superagent` management panel: the `/orchestrator` prefix is
  treated as a privileged route, so a remote request needs the Host/Origin
  (`--trusted-host`) fence plus a valid Access JWT. Loopback is unchanged.

Everything on `main` is a fast-forward of the old `dsh-0.2.1-rc.3` line plus the
superagent work; the historical `dsh-0.2.1-rc.3` and `run-box-superagent`
branches were merged in and can be treated as retired.

## How consumers pin it

`run-boxes` (and any other consumer) pins an immutable commit, never the branch:

```
github:steezypunk/dsh-cloudflare-access#<full-40-char-sha>
```

So `main` may move freely; a pin only changes when we deliberately bump it.

## Branching and merging

- Do work on a topic branch and open a PR into `main`, even though this is our
  own fork. The PR is the review record; merge with **Rebase and merge** so
  `main` stays linear and the PR commit SHAs (which consumers may pin) survive.
- Never **squash** a branch that a consumer has already pinned: squashing
  discards the pinned commit SHAs.
- Committed `lib/` must match a fresh `pnpm build`. CI enforces it; run
  `pnpm build && git status --porcelain` before pushing and keep it clean.
- New behavior needs a test in `test/` and a CHANGELOG entry under
  `## Unreleased`.

## Keeping close to upstream

Upstream `main` is kept as a read-only reference. Rebase our line onto it only
if upstream starts shipping the `0.2.x` work we already carry; otherwise rebase
our topic branches onto our own `main`.

# Changelog

## Unreleased

- Document the listen address: it belongs to DSH's `webserver` row, not this plugin. DSH's Web CLI refuses `--host 0.0.0.0`, so binding all interfaces requires overriding the `webserver` row in the profile patch (plus `--trusted-host`).

## 2.0.0

- Overlay Cloudflare JWT on the original `/api`, `/api/remote.mux`, and index fallback. A valid Access JWT on a remote trusted host skips DSH's launch-token cookie, including Access login callbacks with `sec-fetch-site: cross-site`. Loopback still requires the official token.
- Map privileged RPCs to Typert Remote endpoints (`settings/describe`, `agentPresets/deletePreset`, and the rest of the 0.1.5 configuration surface).
- Treat `/api/remote.mux` as the ordinary events WebSocket.
- Peer `@deepseek-ai/dsh-client-connection` and `@deepseek-ai/dsh-host-webserver` `0.1.5-alpha.1`, plus `@deepseek-ai/cordis` `4.0.2`.

## 1.0.0

- Normalize `teamDomain` to an http(s) origin so a host without `https://` still produces a valid issuer and JWKS URL.
- Skip JWT signature verification when it cannot change the allow/deny decision (`ordinary=off` APIs and failed Host/Origin).
- Skip the `prepare` build during dependency installs so `github:` installs use committed `lib/` without TypeScript or esbuild.
- Fail CI when committed `lib/` does not match a fresh `pnpm build`.
- Allow 30 seconds of clock skew on JWT `exp` / `nbf` so Origin time drift does not reject live Access tokens.
- Return 502 from the privileged HTTP bridge when `apiProxy.fetch` throws, instead of leaving the client hanging.
- Cover loopback wrap, missing `apiProxy`, events upgrade denial, unsigned JWT, and future `nbf` in tests.
- Enable weekly Dependabot for npm and GitHub Actions. Document npm provenance for the next publish (v0.1.0 did not include it).
- Use the same 401/403 split on `/api/events.*` upgrades as on HTTP APIs. Handshake still fails; only the status line changes for invalid tokens.
- Stop committing unused `lib/client/index.js`; the browser runtime is `lib/client.js`.
- Tighten the README (quick start, placeholder audience values, user vs maintainer sections) and add a Chinese README aligned with the English README. Architecture figures are English Archify HTML and SVG in `docs/assets/archify/`.

## 0.1.0

- Initial release: Cloudflare Access JWT verification at the DSH Origin.
- Remote privileged authorization for the settings / credentials / agentPreset management / `llm.discoverModels` plane.
- Ordinary API modes `off | optional | required`.
- Web Client capability enablement for remote Settings, with `dsh.client.immediately: true` so the module is prefetched before `ui-settings` snapshots loopback state.
- Official `dsh.bundle` and `dsh.client` packaging for `dsh plugin --profile web add`.

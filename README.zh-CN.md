# dsh-cloudflare-access

[English](./README.md)

面向 [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness) 的 Cloudflare Access JWT 再验证与远程 privileged 授权。

这是双面 **Profile Bundle + Web Client** 插件。它**不**替代 Cloudflare Access。身份仍在 Access。插件在 DSH Origin 再验证 `Cf-Access-Jwt-Assertion`，使 Settings、Credentials、Agent Preset 管理和模型发现可以在 `https://dsh.example.com` 这类远程主机名上工作。

不提供登录页、密码库、MFA、会话表或 Cloudflare API 客户端。

插件 **`2.0.x`** 对准 DeepSeek Harness **`0.1.5-alpha.1`**。插件 **`1.0.x`** 是 DSH `0.1.2` 之前那条线（live 验证于 `0.1.1-rc.2`）。在[兼容性矩阵](#兼容性)更新之前，不要默认其他 DSH 版本可用。

## 架构

插件运行在 DSH 进程内。它不替代 Cloudflare Access，也不替代 Origin 允许名单。

![Deployment model](./docs/assets/archify/deployment.svg)

```text
Internet → Cloudflare Access → Cloudflare Proxy
       → Origin allowlist → reverse proxy → DSH → this plugin
```

Web Client 只做 capability enablement（`connection.isLoopback`）。授权裁决留在 Origin 上的 Server。

![Client vs Server](./docs/assets/archify/client-server.svg)

交互图（切换主题、Guided Views、导出 SVG/PNG）：[deployment](./docs/assets/archify/deployment.html)、[request path](./docs/assets/archify/privileged-request.html)、[client vs server](./docs/assets/archify/client-server.html)、[config](./docs/assets/archify/config-precedence.html)。说明见 [`docs/diagrams.md`](./docs/diagrams.md)。

## 快速开始

1. 使用 DeepSeek Harness **Web** profile。用 `--trusted-host` 钉住公网主机名。
2. 把该 Origin 放到 Cloudflare Access 应用后面。
3. 安装并重启：

```sh
dsh plugin --profile web add dsh-cloudflare-access
```

4. 锁定信任根（生产环境建议如此）：

```sh
export DSH_CF_ACCESS_TEAM_DOMAIN=https://example.cloudflareaccess.com
export DSH_CF_ACCESS_AUDIENCES=your-access-application-aud
```

5. 经 Access 打开站点并硬刷新一次，再打开 Settings。Origin 上有效的 `Cf-Access-Jwt-Assertion` 会代替远程 Host 上的 DSH launch-token Cookie。loopback 仍须使用 `dsh web` 打印的 `?token=` URL。

用 `dsh --profile web --dump-config` 确认 bundle：应有一层名为 `dsh-cloudflare-access`，以及插件行 `id: cloudflare-access`。

## 安全模型

远程 privileged 请求必须**同时**通过：

1. DSH 的 Host / Origin / `sec-fetch-site` 检查（`--trusted-host` 仍是必须的）。
2. 有效的 Cloudflare Access JWT（签名、`iss`、`aud`、过期时间；允许约 30 秒时钟偏差）。

有效 JWT 永远不能授权任意 Host 或 Origin。Loopback（`localhost` / `127.0.0.1` / `::1`）不要求 JWT，因此 `SSH Tunnel → localhost → DSH` 仍然可用。v2.0 中远程 privileged API 始终要求 JWT。

Origin 应只对 Cloudflare（或等价入口）可达。安装本插件不是把 DSH 挂到公网的理由。详见 [SECURITY.md](./SECURITY.md)。

![Remote privileged request path](./docs/assets/archify/privileged-request.svg)

先做 Host/Origin。有效 JWT 不得把 Host 改写为 loopback。privileged 成功交给原 `/api` handler（DSH Remote）；远程信任主机上有效 Access JWT 同时跳过 DSH launch-token Cookie。缺失或无效 JWT 返回 401/403，且不进入 privileged 业务实现。Loopback 不读 JWT，仍走官方 token/Cookie。

转发 `Host`、`Origin` 和 `Cf-Access-Jwt-Assertion`。不要剥掉 assertion 头。不要信任 `CF_Authorization` Cookie。

## 安装

需要 **Web** profile。包在 [npm](https://www.npmjs.com/package/dsh-cloudflare-access)。

```sh
dsh plugin --profile web add dsh-cloudflare-access
```

未发布的 Git commit：

```sh
dsh plugin --profile web add github:Luawig/dsh-cloudflare-access
```

Git 树已包含预构建的 `lib/index.js` 和 `lib/client.js`。`github:` 安装使用这些产物，不需要 TypeScript 或 esbuild。

重启 DSH。不要手工编辑 `$DSH_HOME/profiles/web/cordis.patch.yml`，也不要改 DSH 本体。

卸载：

```sh
dsh plugin --profile web remove dsh-cloudflare-access
```

unload 后，本插件的 JWT 包装消失。若运行中的进程仍是旧 fiber，再重启一次。

## 配置

1. 把 DSH Web origin 放到 Cloudflare Access 应用后面。
2. 复制应用的 **Audience**（`aud`）和 team domain，例如 `https://example.cloudflareaccess.com`（省略 `https://` 的主机名也可以）。
3. Cloudflare 会在已认证请求上注入 `Cf-Access-Jwt-Assertion`。该头是本插件读取的唯一身份。

team domain 规范化为 http(s) origin（路径丢弃）后，推导 issuer 与 JWKS URL：

```text
issuer  = <origin>
JWKS    = <origin>/cdn-cgi/access/certs
```

不要配置 `issuer` 或 `jwksUrl`。支持多个 audience。

![Configuration precedence](./docs/assets/archify/config-precedence.svg)

生产环境用环境变量钉住 team domain 和 audience。变量一旦存在（即使是空字符串），该字段即锁定，无法从远程 Settings 会话改指向。

| 变量 | 含义 |
| --- | --- |
| `DSH_CF_ACCESS_TEAM_DOMAIN` | Team domain / issuer |
| `DSH_CF_ACCESS_AUDIENCES` | 逗号分隔的 audience |
| `DSH_CF_ACCESS_ORDINARY_MODE` | `off` \| `optional` \| `required` |

```sh
dsh --profile web --trusted-host dsh.example.com
```

systemd：

```ini
[Service]
Environment=DSH_CF_ACCESS_TEAM_DOMAIN=https://example.cloudflareaccess.com
Environment=DSH_CF_ACCESS_AUDIENCES=your-access-application-aud
Environment=DSH_CF_ACCESS_ORDINARY_MODE=off
ExecStart=/usr/bin/dsh --profile web --trusted-host dsh.example.com
```

Cordis overlay（仅当对应 env 未设置时使用）：

```yaml
cloudflare:
  teamDomain: https://example.cloudflareaccess.com
  audiences:
    - your-access-application-aud
auth:
  ordinary: off
```

缺少 `teamDomain` 或 `audiences`：插件仍会启动，loopback 不变，远程 privileged API 被拒绝。

### 监听地址（127.0.0.1 vs 0.0.0.0）

监听地址属于 DSH，不属于本插件。组合后的 `webserver` 行为 `host: ctx.webStartup.host ?? '127.0.0.1'`；本插件只包装 `webServer.register*`，从不自己开 socket。

当前 DSH Web CLI 会主动拒绝 `--host 0.0.0.0`：

```text
error: --host 0.0.0.0 is intentionally not supported yet for safety:
it would expose remote code execution to the network; use 127.0.0.1 instead
```

若要让容器或虚拟机内的反向代理经网络访问 DSH，需在 profile patch 中覆盖 `webserver` 行。覆盖会整行替换 **整个** `config`，因此要一并写回 `port` 与压缩参数：

```yaml
# $DSH_HOME/profiles/web/cordis.patch.yml
- id: webserver
  config:
    host: '0.0.0.0'
    port: 3080
    compression: gzip
    compressionLevel: 1
    compressionThresholdBytes: 1024
```

之后远程信任栅栏仍需认得你的公网主机名：

```sh
dsh --profile web --trusted-host dsh.example.com
```

`0.0.0.0` 会把 DSH 暴露到所有网卡。请确保 Origin 只能从 Cloudflare 或你的代理访问，并设置 `DSH_CF_ACCESS_ORDINARY_MODE=required`，让每次远程 `/api` 调用都必须携带有效 JWT。Loopback 仍然跳过 JWT，但仍需要 DSH 自身的 token/cookie。Cloudflare Tunnel 或 SSH 隧道连到 `127.0.0.1` 不需要上述任何操作，仍是更安全的默认做法。

## 普通 API 模式

`auth.ordinary` 只作用于**远程非特权** API，包括 `/api/remote.mux`。Loopback 忽略它。Host/Origin 始终先执行。

| 模式 | 无 JWT | 有效 JWT | 无效 JWT |
| --- | --- | --- | --- |
| `off`（默认） | DSH 原策略 | 忽略 | 忽略 |
| `optional` | DSH 原策略 | 放行 | 拒绝 |
| `required` | 拒绝 | 放行 | 拒绝 |

无论该设置如何，远程 privileged API 始终要求有效 JWT。

## 排障

| 现象 | 检查 |
| --- | --- |
| 远程 Settings 仍不可用 | Access 必须在站点前面；硬刷新，使 Client 模块在 Settings 之前加载；确认 `Cf-Access-Jwt-Assertion` 到达 Origin。 |
| Settings UI 从不调用 `settings/describe` | 本包设置了 `dsh.client.immediately: true`。若旧 tarball 漏了该项，重新安装。 |
| `settings/*` 返回 401 | Access header 缺失或未被转发。查反向代理是否转发 `Cf-Access-Jwt-Assertion`。loopback 仍须打开 `dsh web` 打印的 `?token=` URL。 |
| `settings/*` 返回 403 | `iss`/`aud`/签名/过期无效、插件未配置、Host/Origin 不匹配，或 Origin 时钟偏差超过约 30 秒。 |
| `ordinary=required` 时事件 WebSocket 失败 | `/api/remote.mux` 走普通 API 策略。缺 JWT → 401；无效 JWT → 403。 |
| Loopback Settings 坏了 | 卸载插件；loopback 不得要求 JWT。若仍要求，请报 bug。 |
| JWKS / 密钥轮换失败 | Origin 必须能访问 `https://<team>/cdn-cgi/access/certs`。Cloudflare 轮换密钥后无需改配置。 |
| 日志 | 只记录类别（`expired`、`invalid_signature`、`issuer_mismatch`、`audience_mismatch`、`missing_token`、`jwks_unavailable`、`unconfigured`）。从不记录 token。 |

本插件不授权 `host.pickDirectory` 或 `host.openPath`。部分 native-host UI 仍可能出现。

## 兼容性

| 插件 | DSH | 状态 |
| --- | --- | --- |
| 1.0.x | 0.1.1-rc.2（0.1.2 之前） | Live 验证（Web profile，远程 Settings / Credentials）。走 `apiProxy` + privileged pin。与 DSH 0.1.2+ 不兼容。 |
| 2.0.x | 0.1.5-alpha.1 | 已在 Cloudflare Access 后的 Web profile 上 live 验证（远程 Settings 不需要 DSH `?token=`）。单元/集成测试。CI 不启动 DSH 进程。 |

在本矩阵更新之前，不要默认更新的 DSH 版本可用。

## 开发

```sh
pnpm install
pnpm test
pnpm typecheck
pnpm pack:check
```

改源码后执行 `pnpm build`，使提交的 `lib/` 与 `src/` 一致。CI 会重建 `lib/`，树不一致则失败。

```sh
dsh plugin --profile web add ./
```

插件打包遵循 [dsh.pub/develop-plugin.md](https://dsh.pub/develop-plugin.md)。本仓库不声称已有 dsh.pub listing 或安全审计。

### 维护者

Dependabot 每周更新 npm 和 GitHub Actions。从 GitHub Actions 发布时，使用 `npm publish --access public --provenance`，并授予 `id-token: write`。v0.1.0 和 v1.0.0 发布时没有 provenance。

## License

MIT

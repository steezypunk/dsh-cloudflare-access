/**
 * DSH 0.1.5-alpha.1 没有公开 authorization hook。
 * `connection.requestRejection` 是同步的（Host/Origin + browser-session Cookie），
 * 装不下 jose JWKS 异步验签。因此 inject `webServer`，在 connection 注册 `/api`
 * 之前包装 register / registerUpgrade，把 Cloudflare JWT 叠在原 handler 前面。
 *
 * 远程 + 有效 Access JWT：跳过 DSH launch-token Cookie（Access 已证明身份）。
 * loopback 仍走官方 token/Cookie（Access 罩不到本机端口）。
 */
import type { IncomingMessage, ServerResponse } from 'node:http'
import type { Duplex } from 'node:stream'
import type { PluginConfig } from '../config.ts'
import { httpStatusFor, logDenied, type PluginLogger } from '../server/authorization.ts'
import type { JwtVerifier } from '../server/cloudflare-jwt.ts'
import { decide, jwtParticipates } from '../server/policy.ts'
import { readAccessJwt, type JwtVerification } from '../server/types.ts'
import { API_PATH, REMOTE_STREAM_MUX_PATH, rpcMethodFromUrl } from './api-path.ts'
import { isTrustedApiRequest, requestIsLoopback, requestRemoteHostTrusted } from './dsh-trust.ts'

export interface WebRoute {
  kind: 'exact' | 'prefix'
  path: string
  handler: (req: IncomingMessage, res: ServerResponse) => void | Promise<void>
}

export interface WebUpgradeRoute {
  path: string
  handler: (req: IncomingMessage, socket: Duplex, head: Buffer) => void | Promise<void>
}

export interface WebServerLike {
  register(route: WebRoute): () => void
  registerUpgrade(route: WebUpgradeRoute): () => void
  registerFallback?(handler: WebRoute['handler']): () => void
}

export interface ConnectionAdmission {
  peer?: unknown
  rejection?: 401 | 403
}

export interface ConnectionAuthLike {
  requestRejection(request: IncomingMessage): 401 | 403 | undefined
  authorizeIndex(request: IncomingMessage, response: ServerResponse): boolean
  /** DSH 0.2.1's /api route calls admit() directly instead of requestRejection(). */
  admit?(request: IncomingMessage): ConnectionAdmission
  browserPeer?: unknown
}

export interface CompatFiber {
  connection?: ConnectionAuthLike
  get?(name: string): unknown
}

export interface CompatContext {
  webServer: WebServerLike
  logger?: PluginLogger
  effect(callback: () => (() => void) | Promise<void>, name?: string): void
  get(name: string): unknown
  inject?(deps: readonly string[], callback: (fiber: CompatFiber) => void): void
}

export interface ServerCompatDeps {
  config: PluginConfig
  verifier: JwtVerifier
  getTrustedHosts: () => readonly string[]
}

type Gate =
  | { action: 'forward'; skipBrowserSession: boolean }
  | {
      action: 'deny'
      status: 401 | 403
      body: string
      method: string | undefined
      privileged: boolean
      reason: ReturnType<typeof decide>['reason']
    }

const MISSING_JWT: JwtVerification = {
  outcome: 'missing',
  reason: 'missing_token',
  audienceMatched: null,
}

function nodeHeaders(req: IncomingMessage): Record<string, string | string[] | undefined> {
  return req.headers
}

function writeAuth(res: ServerResponse, status: 401 | 403, body: string): void {
  res.writeHead(status)
  res.end(body)
}

function rejectUpgrade(socket: Duplex, status: 401 | 403): void {
  const reason = status === 401 ? 'Unauthorized' : 'Forbidden'
  socket.write(`HTTP/1.1 ${status} ${reason}\r\nConnection: close\r\n\r\n`)
  socket.destroy()
}

function isApiPrefix(route: WebRoute): boolean {
  return route.kind === 'prefix' && route.path === API_PATH
}

function isRemoteMuxUpgrade(route: WebUpgradeRoute): boolean {
  return route.path === REMOTE_STREAM_MUX_PATH
}

function connectionFrom(fiber: CompatFiber): ConnectionAuthLike | undefined {
  if (fiber.connection !== undefined) return fiber.connection
  const found = fiber.get?.('connection')
  if (found !== undefined && typeof found === 'object' && found !== null
    && 'requestRejection' in found && 'authorizeIndex' in found) {
    return found as ConnectionAuthLike
  }
  return undefined
}

function restoreMethod<K extends 'requestRejection' | 'authorizeIndex'>(
  connection: ConnectionAuthLike,
  key: K,
  original: ConnectionAuthLike[K],
  hadOwn: boolean,
): void {
  if (hadOwn) {
    connection[key] = original
    return
  }
  delete (connection as Partial<ConnectionAuthLike>)[key]
}

function wrapBrowserSession(
  connection: ConnectionAuthLike,
  skipped: WeakSet<IncomingMessage>,
  effect: CompatContext['effect'],
): void {
  const hadOwnRejection = Object.prototype.hasOwnProperty.call(connection, 'requestRejection')
  const hadOwnIndex = Object.prototype.hasOwnProperty.call(connection, 'authorizeIndex')
  const hadOwnAdmit = Object.prototype.hasOwnProperty.call(connection, 'admit')
  const originalRejection = connection.requestRejection
  const originalIndex = connection.authorizeIndex
  const originalAdmitMethod = connection.admit
  const originalAdmit = originalAdmitMethod?.bind(connection)

  connection.requestRejection = (request) => {
    const rejection = originalRejection.call(connection, request)
    if (rejection === 401 && skipped.has(request)) return undefined
    return rejection
  }
  connection.authorizeIndex = (request, response) => {
    if (skipped.has(request)) return true
    return originalIndex.call(connection, request, response)
  }
  if (originalAdmit !== undefined) {
    connection.admit = (request) => {
      // The route gate runs first and marks a request whose Cloudflare JWT is
      // valid. DSH 0.2.1's /api handler then calls admit() directly, bypassing
      // requestRejection(); hand it the shared browser peer explicitly.
      if (skipped.has(request) && connection.browserPeer !== undefined) {
        return { peer: connection.browserPeer }
      }
      return originalAdmit(request)
    }
  }

  effect(() => () => {
    restoreMethod(connection, 'requestRejection', originalRejection, hadOwnRejection)
    restoreMethod(connection, 'authorizeIndex', originalIndex, hadOwnIndex)
    if (originalAdmitMethod !== undefined) {
      if (hadOwnAdmit) connection.admit = originalAdmitMethod
      else delete (connection as Partial<ConnectionAuthLike>).admit
    }
  }, 'dsh-cloudflare-access: restore connection browser-session')
}

/**
 * Wrap webServer.register / registerUpgrade / registerFallback.
 * Must run before connection apply. Restores originals on dispose.
 */
export function installServerCompat(ctx: CompatContext, deps: ServerCompatDeps): void {
  const originalRegister = ctx.webServer.register
  const originalRegisterUpgrade = ctx.webServer.registerUpgrade
  const originalRegisterFallback = ctx.webServer.registerFallback?.bind(ctx.webServer)
  const logger: PluginLogger = ctx.logger ?? { info() {}, warn() {} }
  const skipped = new WeakSet<IncomingMessage>()

  const markAndForward = (req: IncomingMessage, skip: boolean): void => {
    if (skip) skipped.add(req)
  }

  ctx.webServer.register = (route: WebRoute): (() => void) => {
    if (!isApiPrefix(route)) return originalRegister.call(ctx.webServer, route)
    const inner = route.handler
    return originalRegister.call(ctx.webServer, {
      ...route,
      handler: async (req, res) => {
        const gate = await authorize(req, deps)
        if (gate.action === 'deny') {
          logDenied(logger, {
            method: gate.method,
            reason: gate.reason,
            privileged: gate.privileged,
          })
          writeAuth(res, gate.status, gate.body)
          return
        }
        markAndForward(req, gate.skipBrowserSession)
        await inner(req, res)
      },
    })
  }

  ctx.webServer.registerUpgrade = (route: WebUpgradeRoute): (() => void) => {
    if (!isRemoteMuxUpgrade(route)) return originalRegisterUpgrade.call(ctx.webServer, route)
    const inner = route.handler
    return originalRegisterUpgrade.call(ctx.webServer, {
      ...route,
      handler: async (req, socket, head) => {
        const gate = await authorize(req, deps)
        if (gate.action === 'deny') {
          logDenied(logger, {
            method: gate.method,
            reason: gate.reason,
            privileged: gate.privileged,
          })
          rejectUpgrade(socket, gate.status)
          return
        }
        markAndForward(req, gate.skipBrowserSession)
        await inner(req, socket, head)
      },
    })
  }

  if (originalRegisterFallback !== undefined) {
    ctx.webServer.registerFallback = (handler: WebRoute['handler']): (() => void) => {
      return originalRegisterFallback(async (req, res) => {
        const gate = await authorize(req, deps)
        if (gate.action === 'deny') {
          logDenied(logger, {
            method: gate.method,
            reason: gate.reason,
            privileged: gate.privileged,
          })
          writeAuth(res, gate.status, gate.body)
          return
        }
        markAndForward(req, gate.skipBrowserSession)
        await handler(req, res)
      })
    }
  }

  if (typeof ctx.inject === 'function') {
    ctx.inject(['connection'], (fiber) => {
      const connection = connectionFrom(fiber)
      if (connection === undefined) return
      wrapBrowserSession(connection, skipped, ctx.effect)
    })
  }

  ctx.effect(() => () => {
    ctx.webServer.register = originalRegister
    ctx.webServer.registerUpgrade = originalRegisterUpgrade
    if (originalRegisterFallback !== undefined) {
      ctx.webServer.registerFallback = originalRegisterFallback
    }
  }, 'dsh-cloudflare-access: restore webServer.register')
}

/**
 * Loopback 交给原 handler（DSH 自己走 token/Cookie）。
 * Access 登录回调经常是 `sec-fetch-site: cross-site` 导航，跳过 Cookie 只要求 Host 在 `--trusted-host` 中且 JWT 有效，不套用完整 Origin 栅栏。policy deny 仍要求完整 Host/Origin。
 */
async function authorize(req: IncomingMessage, deps: ServerCompatDeps): Promise<Gate> {
  const headers = nodeHeaders(req)
  if (requestIsLoopback(headers)) return { action: 'forward', skipBrowserSession: false }

  const trustedHosts = deps.getTrustedHosts()
  const remoteHostTrusted = requestRemoteHostTrusted(headers, trustedHosts)
  const hostOriginTrusted = isTrustedApiRequest(headers, trustedHosts)

  const method = rpcMethodFromUrl(req.url)
  const token = readAccessJwt(headers)
  const tokenPresent = token !== undefined && token.trim() !== ''
  const needPolicyJwt = hostOriginTrusted && jwtParticipates({
    method,
    ordinary: deps.config.ordinary,
    tokenPresent,
  })
  let jwt = MISSING_JWT
  if (needPolicyJwt || (remoteHostTrusted && tokenPresent)) {
    jwt = await deps.verifier.verify(headers)
  }

  const skipBrowserSession = remoteHostTrusted && jwt.outcome === 'valid'
  if (!hostOriginTrusted || !needPolicyJwt) {
    return { action: 'forward', skipBrowserSession }
  }

  const decision = decide({
    isLoopback: false,
    hostOriginTrusted: true,
    method,
    ordinary: deps.config.ordinary,
    jwt,
  })
  if (decision.effect !== 'deny') return { action: 'forward', skipBrowserSession }

  const http = httpStatusFor(decision)
  return {
    action: 'deny',
    status: http?.status ?? 401,
    body: http?.body ?? 'unauthorized',
    method,
    privileged: decision.class === 'privileged',
    reason: decision.reason,
  }
}

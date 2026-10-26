import { isCloudflareConfigured, issuerOf, resolveConfig, type CordisConfig } from '../config.ts'
import { installServerCompat } from '../compat/dsh.ts'
import { logBoot, type PluginLogger } from './authorization.ts'
import { createJwtVerifier } from './cloudflare-jwt.ts'

export type { CordisConfig, PluginConfig } from '../config.ts'
export { resolveConfig, isCloudflareConfigured, issuerOf, jwksUrlOf } from '../config.ts'
export { createJwtVerifier, CLOCK_TOLERANCE_SECONDS } from './cloudflare-jwt.ts'
export { decide, PRIVILEGED_METHODS, jwtParticipates } from './policy.ts'

export const name = 'cloudflare-access'
export const inject = ['webServer']

export interface ServerPluginContext {
  webServer: {
    register(route: unknown): () => void
    registerUpgrade(route: unknown): () => void
    registerFallback?(handler: unknown): () => void
  }
  logger?: PluginLogger
  effect(callback: () => (() => void) | Promise<void>, name?: string): void
  get(name: string): unknown
  inject?(deps: readonly string[], callback: (fiber: unknown) => void): void
}

function trustedHostsFrom(ctx: ServerPluginContext): readonly string[] {
  const runtime = ctx.get('webRuntime') as { trustedHosts?: string[] } | undefined
  if (runtime?.trustedHosts !== undefined && runtime.trustedHosts.length > 0) {
    return runtime.trustedHosts
  }
  // DSH 0.2.1 moved the fence's trusted-host list to the Connection service.
  const connection = ctx.get('connection') as { trustedHosts?: string[] } | undefined
  if (connection?.trustedHosts !== undefined && connection.trustedHosts.length > 0) {
    return connection.trustedHosts
  }
  const hosts: string[] = []
  const argv = process.argv
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]!
    if (arg === '--trusted-host' && argv[i + 1] !== undefined) hosts.push(argv[i + 1] as string)
    else if (argv[i]?.startsWith('--trusted-host=')) hosts.push(arg.slice('--trusted-host='.length))
  }
  return hosts
}

export function apply(ctx: ServerPluginContext, config?: CordisConfig): void {
  const resolved = resolveConfig(config, process.env)
  const logger: PluginLogger = ctx.logger ?? { info() {}, warn() {} }
  logBoot(logger, {
    configured: isCloudflareConfigured(resolved),
    audienceCount: resolved.audiences.length,
    ordinary: resolved.ordinary,
    issuer: issuerOf(resolved),
  })
  const verifier = createJwtVerifier(resolved)
  installServerCompat(ctx as never, {
    config: resolved,
    verifier,
    getTrustedHosts: () => trustedHostsFrom(ctx),
  })
}

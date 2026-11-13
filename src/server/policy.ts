import type { OrdinaryMode } from '../config.ts'
import type { JwtFailureReason, JwtVerification } from './types.ts'

/**
 * Synthetic method for the dsh-superagent management panel (`/orchestrator`).
 * Its routes are not Typert Remote endpoints, but the panel exposes repository,
 * account, policy, and prompt control with no authentication of its own, so a
 * remote request is always privileged: the Host/Origin fence plus a valid
 * Access JWT are required.
 */
export const ORCHESTRATOR_METHOD = 'orchestrator/management'

/**
 * Remote methods this plugin may authorize with a valid JWT.
 * Names match DSH 0.1.5-alpha.1 Typert Remote endpoints (`namespace/method`).
 * Native directory-picker / host.openPath stay off this list.
 */
export const PRIVILEGED_METHODS = new Set<string>([
  'settings/describe',
  'settings/openSettingsDocument',
  'settings/update',
  'settings/replace',
  'settings/mutate',
  'settings/canOpenAgentPresetDirectory',
  'settings/openAgentPresetDirectory',
  'credentials/describe',
  'credentials/set',
  'credentials/unset',
  'agentPresets/read',
  'agentPresets/copy',
  'agentPresets/deletePreset',
  'llm/discoverModels',
  ORCHESTRATOR_METHOD,
])

export type AuthClass = 'loopback' | 'privileged' | 'ordinary'

export interface AuthDecision {
  effect: 'allow' | 'deny'
  class: AuthClass
  reason: JwtFailureReason | 'host_origin_rejected' | null
}

export interface PolicyInput {
  isLoopback: boolean
  hostOriginTrusted: boolean
  method: string | undefined
  ordinary: OrdinaryMode
  jwt: JwtVerification
}

function deny(authClass: AuthClass, reason: AuthDecision['reason']): AuthDecision {
  return { effect: 'deny', class: authClass, reason }
}

function allow(authClass: AuthClass): AuthDecision {
  return { effect: 'allow', class: authClass, reason: null }
}

export function isPrivilegedMethod(method: string | undefined): boolean {
  return method !== undefined && PRIVILEGED_METHODS.has(method)
}

/**
 * Whether cryptographic JWT verification can change the decision.
 * Host/Origin failure and loopback are handled before this is consulted.
 */
export function jwtParticipates(input: {
  method: string | undefined
  ordinary: OrdinaryMode
  tokenPresent: boolean
}): boolean {
  if (isPrivilegedMethod(input.method)) return true
  switch (input.ordinary) {
    case 'off':
      return false
    case 'optional':
      return input.tokenPresent
    case 'required':
      return true
  }
}

function jwtOk(jwt: JwtVerification): boolean {
  return jwt.outcome === 'valid'
}

/**
 * Pure authorization decision. Host/Origin is consumed as a boolean; this
 * function never inspects headers and never treats JWT as a Host substitute.
 */
export function decide(input: PolicyInput): AuthDecision {
  if (input.isLoopback) return allow('loopback')
  if (!input.hostOriginTrusted) return deny(isPrivilegedMethod(input.method) ? 'privileged' : 'ordinary', 'host_origin_rejected')

  if (isPrivilegedMethod(input.method)) {
    if (jwtOk(input.jwt)) return allow('privileged')
    return deny('privileged', input.jwt.reason ?? 'missing_token')
  }

  switch (input.ordinary) {
    case 'off':
      return allow('ordinary')
    case 'optional':
      if (input.jwt.outcome === 'missing') return allow('ordinary')
      if (jwtOk(input.jwt)) return allow('ordinary')
      return deny('ordinary', input.jwt.reason ?? 'malformed')
    case 'required':
      if (jwtOk(input.jwt)) return allow('ordinary')
      return deny('ordinary', input.jwt.reason ?? 'missing_token')
  }
}

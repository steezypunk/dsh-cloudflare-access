import type { OrdinaryMode } from '../config.ts';
import type { JwtFailureReason, JwtVerification } from './types.ts';
/**
 * Synthetic method for the dsh-superagent management panel (`/orchestrator`).
 * Its routes are not Typert Remote endpoints, but the panel exposes repository,
 * account, policy, and prompt control with no authentication of its own, so a
 * remote request is always privileged: the Host/Origin fence plus a valid
 * Access JWT are required.
 */
export declare const ORCHESTRATOR_METHOD = "orchestrator/management";
/**
 * Remote methods this plugin may authorize with a valid JWT.
 * Names match DSH 0.1.5-alpha.1 Typert Remote endpoints (`namespace/method`).
 * Native directory-picker / host.openPath stay off this list.
 */
export declare const PRIVILEGED_METHODS: Set<string>;
export type AuthClass = 'loopback' | 'privileged' | 'ordinary';
export interface AuthDecision {
    effect: 'allow' | 'deny';
    class: AuthClass;
    reason: JwtFailureReason | 'host_origin_rejected' | null;
}
export interface PolicyInput {
    isLoopback: boolean;
    hostOriginTrusted: boolean;
    method: string | undefined;
    ordinary: OrdinaryMode;
    jwt: JwtVerification;
}
export declare function isPrivilegedMethod(method: string | undefined): boolean;
/**
 * Whether cryptographic JWT verification can change the decision.
 * Host/Origin failure and loopback are handled before this is consulted.
 */
export declare function jwtParticipates(input: {
    method: string | undefined;
    ordinary: OrdinaryMode;
    tokenPresent: boolean;
}): boolean;
/**
 * Pure authorization decision. Host/Origin is consumed as a boolean; this
 * function never inspects headers and never treats JWT as a Host substitute.
 */
export declare function decide(input: PolicyInput): AuthDecision;
//# sourceMappingURL=policy.d.ts.map
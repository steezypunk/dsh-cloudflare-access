/**
 * DSH 0.1.5-alpha.1 没有公开 authorization hook。
 * `connection.requestRejection` 是同步的（Host/Origin + browser-session Cookie），
 * 装不下 jose JWKS 异步验签。因此 inject `webServer`，在 connection 注册 `/api`
 * 之前包装 register / registerUpgrade，把 Cloudflare JWT 叠在原 handler 前面。
 *
 * 远程 + 有效 Access JWT：跳过 DSH launch-token Cookie（Access 已证明身份）。
 * loopback 仍走官方 token/Cookie（Access 罩不到本机端口）。
 */
import type { IncomingMessage, ServerResponse } from 'node:http';
import type { Duplex } from 'node:stream';
import type { PluginConfig } from '../config.ts';
import { type PluginLogger } from '../server/authorization.ts';
import type { JwtVerifier } from '../server/cloudflare-jwt.ts';
export interface WebRoute {
    kind: 'exact' | 'prefix';
    path: string;
    handler: (req: IncomingMessage, res: ServerResponse) => void | Promise<void>;
}
export interface WebUpgradeRoute {
    path: string;
    handler: (req: IncomingMessage, socket: Duplex, head: Buffer) => void | Promise<void>;
}
export interface WebServerLike {
    register(route: WebRoute): () => void;
    registerUpgrade(route: WebUpgradeRoute): () => void;
    registerFallback?(handler: WebRoute['handler']): () => void;
    /** DSH 0.2.1 exposes its route tables; used to wrap routes registered before this plugin. */
    exact?: Map<string, WebRoute>;
    prefixes?: Map<string, WebRoute>;
    upgrades?: Map<string, WebUpgradeRoute>;
}
export interface ConnectionAdmission {
    peer?: unknown;
    rejection?: 401 | 403;
}
export interface ConnectionAuthLike {
    requestRejection(request: IncomingMessage): 401 | 403 | undefined;
    authorizeIndex(request: IncomingMessage, response: ServerResponse): boolean;
    /** DSH 0.2.1's /api route calls admit() directly instead of requestRejection(). */
    admit?(request: IncomingMessage): ConnectionAdmission;
    browserPeer?: unknown;
}
export interface CompatFiber {
    connection?: ConnectionAuthLike;
    get?(name: string): unknown;
}
export interface CompatContext {
    webServer: WebServerLike;
    logger?: PluginLogger;
    effect(callback: () => (() => void) | Promise<void>, name?: string): void;
    get(name: string): unknown;
    inject?(deps: readonly string[], callback: (fiber: CompatFiber) => void): void;
}
export interface ServerCompatDeps {
    config: PluginConfig;
    verifier: JwtVerifier;
    getTrustedHosts: () => readonly string[];
}
/**
 * Wrap webServer.register / registerUpgrade / registerFallback.
 * Must run before connection apply. Restores originals on dispose.
 */
export declare function installServerCompat(ctx: CompatContext, deps: ServerCompatDeps): void;
//# sourceMappingURL=dsh.d.ts.map
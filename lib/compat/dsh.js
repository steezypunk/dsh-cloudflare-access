import { httpStatusFor, logDenied } from "../server/authorization.js";
import { decide, jwtParticipates, ORCHESTRATOR_METHOD } from "../server/policy.js";
import { readAccessJwt } from "../server/types.js";
import { API_PATH, ORCHESTRATOR_PATH, REMOTE_STREAM_MUX_PATH, rpcMethodFromUrl } from "./api-path.js";
import { isTrustedApiRequest, requestIsLoopback, requestRemoteHostTrusted } from "./dsh-trust.js";
const MISSING_JWT = {
    outcome: 'missing',
    reason: 'missing_token',
    audienceMatched: null,
};
function requestHeaders(req) {
    return req.headers;
}
function writeAuth(res, status, body) {
    res.writeHead(status);
    res.end(body);
}
function rejectUpgrade(socket, status) {
    const reason = status === 401 ? 'Unauthorized' : 'Forbidden';
    socket.write(`HTTP/1.1 ${status} ${reason}\r\nConnection: close\r\n\r\n`);
    socket.destroy();
}
function isApiPrefix(route) {
    return route.kind === 'prefix' && route.path === API_PATH;
}
function isRemoteMuxUpgrade(route) {
    return route.path === REMOTE_STREAM_MUX_PATH;
}
function isSidebarPath(path) {
    return path === '/sidebar' || path.startsWith('/sidebar/');
}
function isSidebarRoute(route) {
    return isSidebarPath(route.path);
}
/**
 * The dsh-superagent management panel registers one prefix route at
 * ORCHESTRATOR_PATH and answers ORCHESTRATOR_PATH/api/*. It carries no
 * authentication of its own, so behind a tunnel it is gated like a privileged
 * DSH route: the Host/Origin fence plus a valid Access JWT.
 */
function isOrchestratorRoute(route) {
    return route.kind === 'prefix' && route.path === ORCHESTRATOR_PATH;
}
function isGatedHttpRoute(route) {
    return isApiPrefix(route) || isSidebarRoute(route) || isOrchestratorRoute(route);
}
/** Whether a route registration is answered by a Fetch resource rather than a node handler. */
function isResourceRoute(route) {
    return typeof route.resource === 'function';
}
/** Whether a fallback registration is the DSH 0.2.2 `{ resource }` shape rather than a handler. */
function isResourceFallback(fallback) {
    return typeof fallback === 'object' && fallback !== null
        && typeof fallback.resource === 'function';
}
function isGatedUpgradeRoute(route) {
    return isRemoteMuxUpgrade(route) || isSidebarRoute(route);
}
function connectionFrom(fiber) {
    if (fiber.connection !== undefined)
        return fiber.connection;
    const found = fiber.get?.('connection');
    if (found !== undefined && typeof found === 'object' && found !== null
        && 'requestRejection' in found && 'authorizeIndex' in found) {
        return found;
    }
    return undefined;
}
function restoreMethod(connection, key, original, hadOwn) {
    if (hadOwn) {
        connection[key] = original;
        return;
    }
    delete connection[key];
}
function wrapBrowserSession(connection, skipped, effect) {
    const hadOwnRejection = Object.prototype.hasOwnProperty.call(connection, 'requestRejection');
    const hadOwnIndex = Object.prototype.hasOwnProperty.call(connection, 'authorizeIndex');
    const hadOwnAdmit = Object.prototype.hasOwnProperty.call(connection, 'admit');
    const originalRejection = connection.requestRejection;
    const originalIndex = connection.authorizeIndex;
    const originalAdmitMethod = connection.admit;
    const originalAdmit = originalAdmitMethod?.bind(connection);
    connection.requestRejection = (request) => {
        // skipped is set only after the route gate verified Host/Origin and a valid
        // Access JWT. The connection's own 401/403 fence must not undo that.
        if (skipped.has(request))
            return undefined;
        return originalRejection.call(connection, request);
    };
    connection.authorizeIndex = (request, response) => {
        if (skipped.has(request))
            return true;
        return originalIndex.call(connection, request, response);
    };
    if (originalAdmit !== undefined) {
        connection.admit = (request) => {
            // The route gate runs first and marks a request whose Cloudflare JWT is
            // valid. DSH 0.2.1's /api handler then calls admit() directly, bypassing
            // requestRejection(); hand it the shared browser peer explicitly.
            if (skipped.has(request) && connection.browserPeer !== undefined) {
                return { peer: connection.browserPeer };
            }
            return originalAdmit(request);
        };
    }
    effect(() => () => {
        restoreMethod(connection, 'requestRejection', originalRejection, hadOwnRejection);
        restoreMethod(connection, 'authorizeIndex', originalIndex, hadOwnIndex);
        if (originalAdmitMethod !== undefined) {
            if (hadOwnAdmit)
                connection.admit = originalAdmitMethod;
            else
                delete connection.admit;
        }
    }, 'dsh-cloudflare-access: restore connection browser-session');
}
/**
 * Wrap webServer.register / registerUpgrade / registerFallback.
 * Must run before connection apply. Restores originals on dispose.
 */
export function installServerCompat(ctx, deps) {
    const originalRegister = ctx.webServer.register;
    const originalRegisterUpgrade = ctx.webServer.registerUpgrade;
    const originalRegisterFallback = ctx.webServer.registerFallback?.bind(ctx.webServer);
    const logger = ctx.logger ?? { info() { }, warn() { } };
    // Keyed by whatever object the gate saw: a node request for a handler route,
    // or a Fetch Request for a resource route.
    const skipped = new WeakSet();
    const markAndForward = (request, skip) => {
        if (skip)
            skipped.add(request);
    };
    const wrappedHttpRoutes = new WeakSet();
    const wrappedUpgradeRoutes = new WeakSet();
    const gateHttp = (route) => {
        const inner = route.handler;
        const orchestrator = isOrchestratorRoute(route);
        const wrapped = {
            ...route,
            handler: async (req, res) => {
                const gate = await authorize(req, deps, { orchestrator });
                if (gate.action === 'deny') {
                    logDenied(logger, {
                        method: gate.method,
                        reason: gate.reason,
                        privileged: gate.privileged,
                    });
                    writeAuth(res, gate.status, gate.body);
                    return;
                }
                markAndForward(req, gate.skipBrowserSession);
                await inner(req, res);
            },
        };
        wrappedHttpRoutes.add(wrapped);
        return wrapped;
    };
    /**
     * Wrap a Fetch-resource responder: run the gate, answer a denial as a
     * `Response`, then hand the request to the resource. Used for the DSH 0.2.2
     * `{ resource }` fallback and any resource-answered named route.
     */
    const gateResourceFn = (inner, orchestrator, allowCrossSiteSkip) => {
        return async (request, peer) => {
            const gate = await authorize({ url: request.url, headers: request.headers }, deps, { orchestrator, allowCrossSiteSkip });
            if (gate.action === 'deny') {
                logDenied(logger, {
                    method: gate.method,
                    reason: gate.reason,
                    privileged: gate.privileged,
                });
                return new Response(gate.body, { status: gate.status });
            }
            markAndForward(request, gate.skipBrowserSession);
            return inner(request, peer);
        };
    };
    const gateHttpRoute = (route) => {
        if (isResourceRoute(route)) {
            const wrapped = {
                ...route,
                resource: gateResourceFn(route.resource, isOrchestratorRoute(route), false),
            };
            wrappedHttpRoutes.add(wrapped);
            return wrapped;
        }
        return gateHttp(route);
    };
    const gateUpgrade = (route) => {
        const inner = route.handler;
        const wrapped = {
            ...route,
            handler: async (req, socket, head) => {
                const gate = await authorize(req, deps);
                if (gate.action === 'deny') {
                    logDenied(logger, {
                        method: gate.method,
                        reason: gate.reason,
                        privileged: gate.privileged,
                    });
                    rejectUpgrade(socket, gate.status);
                    return;
                }
                markAndForward(req, gate.skipBrowserSession);
                await inner(req, socket, head);
            },
        };
        wrappedUpgradeRoutes.add(wrapped);
        return wrapped;
    };
    ctx.webServer.register = (route) => {
        if (!isGatedHttpRoute(route))
            return originalRegister.call(ctx.webServer, route);
        return originalRegister.call(ctx.webServer, gateHttpRoute(route));
    };
    ctx.webServer.registerUpgrade = (route) => {
        if (!isGatedUpgradeRoute(route))
            return originalRegisterUpgrade.call(ctx.webServer, route);
        return originalRegisterUpgrade.call(ctx.webServer, gateUpgrade(route));
    };
    const originalRoutes = [];
    const originalUpgrades = [];
    // dsh-better-sidebar registers /sidebar/* before this plugin applies, and its
    // fence calls connection.requestRejection(). Wrap those existing routes too.
    for (const map of [ctx.webServer.exact, ctx.webServer.prefixes]) {
        if (map === undefined)
            continue;
        for (const [path, route] of map) {
            if (!isGatedHttpRoute(route) || wrappedHttpRoutes.has(route))
                continue;
            const wrapped = gateHttpRoute(route);
            map.set(path, wrapped);
            originalRoutes.push({ map, path, route, wrapped });
        }
    }
    if (ctx.webServer.upgrades !== undefined) {
        for (const [path, route] of ctx.webServer.upgrades) {
            if (!isGatedUpgradeRoute(route) || wrappedUpgradeRoutes.has(route))
                continue;
            const wrapped = gateUpgrade(route);
            ctx.webServer.upgrades.set(path, wrapped);
            originalUpgrades.push({ map: ctx.webServer.upgrades, path, route, wrapped });
        }
    }
    if (originalRegisterFallback !== undefined) {
        ctx.webServer.registerFallback = (fallback) => {
            // DSH 0.2.2 claims the fallback seat with `{ resource }` (the SPA dist
            // server); earlier lines registered a bare handler. Gate both.
            if (isResourceFallback(fallback)) {
                return originalRegisterFallback({
                    resource: gateResourceFn(fallback.resource, false, true),
                });
            }
            return originalRegisterFallback(async (req, res) => {
                const gate = await authorize(req, deps, { allowCrossSiteSkip: true });
                if (gate.action === 'deny') {
                    logDenied(logger, {
                        method: gate.method,
                        reason: gate.reason,
                        privileged: gate.privileged,
                    });
                    writeAuth(res, gate.status, gate.body);
                    return;
                }
                markAndForward(req, gate.skipBrowserSession);
                await fallback(req, res);
            });
        };
    }
    if (typeof ctx.inject === 'function') {
        ctx.inject(['connection'], (fiber) => {
            const connection = connectionFrom(fiber);
            if (connection === undefined)
                return;
            wrapBrowserSession(connection, skipped, ctx.effect);
        });
    }
    ctx.effect(() => () => {
        ctx.webServer.register = originalRegister;
        ctx.webServer.registerUpgrade = originalRegisterUpgrade;
        if (originalRegisterFallback !== undefined) {
            ctx.webServer.registerFallback = originalRegisterFallback;
        }
        for (const { map, path, route, wrapped } of originalRoutes) {
            if (map.get(path) === wrapped)
                map.set(path, route);
        }
        for (const { map, path, route, wrapped } of originalUpgrades) {
            if (map.get(path) === wrapped)
                map.set(path, route);
        }
    }, 'dsh-cloudflare-access: restore webServer.register');
}
async function authorize(req, deps, options = {}) {
    const { allowCrossSiteSkip = false, orchestrator = false } = options;
    const headers = requestHeaders(req);
    if (requestIsLoopback(headers))
        return { action: 'forward', skipBrowserSession: false };
    const trustedHosts = deps.getTrustedHosts();
    const remoteHostTrusted = requestRemoteHostTrusted(headers, trustedHosts);
    const hostOriginTrusted = isTrustedApiRequest(headers, trustedHosts);
    const method = orchestrator ? ORCHESTRATOR_METHOD : rpcMethodFromUrl(req.url);
    const token = readAccessJwt(headers);
    const tokenPresent = token !== undefined && token.trim() !== '';
    const needPolicyJwt = hostOriginTrusted && jwtParticipates({
        method,
        ordinary: deps.config.ordinary,
        tokenPresent,
    });
    let jwt = MISSING_JWT;
    if (needPolicyJwt || (remoteHostTrusted && tokenPresent)) {
        jwt = await deps.verifier.verify(headers);
    }
    const skipBrowserSession = remoteHostTrusted && jwt.outcome === 'valid'
        && (hostOriginTrusted || allowCrossSiteSkip);
    if (!hostOriginTrusted || !needPolicyJwt) {
        return { action: 'forward', skipBrowserSession };
    }
    const decision = decide({
        isLoopback: false,
        hostOriginTrusted: true,
        method,
        ordinary: deps.config.ordinary,
        jwt,
    });
    if (decision.effect !== 'deny')
        return { action: 'forward', skipBrowserSession };
    const http = httpStatusFor(decision);
    return {
        action: 'deny',
        status: http?.status ?? 401,
        body: http?.body ?? 'unauthorized',
        method,
        privileged: decision.class === 'privileged',
        reason: decision.reason,
    };
}
//# sourceMappingURL=dsh.js.map
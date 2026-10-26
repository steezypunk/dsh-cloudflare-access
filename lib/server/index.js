import { isCloudflareConfigured, issuerOf, resolveConfig } from "../config.js";
import { installServerCompat } from "../compat/dsh.js";
import { logBoot } from "./authorization.js";
import { createJwtVerifier } from "./cloudflare-jwt.js";
export { resolveConfig, isCloudflareConfigured, issuerOf, jwksUrlOf } from "../config.js";
export { createJwtVerifier, CLOCK_TOLERANCE_SECONDS } from "./cloudflare-jwt.js";
export { decide, PRIVILEGED_METHODS, jwtParticipates } from "./policy.js";
export const name = 'cloudflare-access';
export const inject = ['webServer'];
function trustedHostsFrom(ctx) {
    const runtime = ctx.get('webRuntime');
    if (runtime?.trustedHosts !== undefined && runtime.trustedHosts.length > 0) {
        return runtime.trustedHosts;
    }
    // DSH 0.2.1 moved the fence's trusted-host list to the Connection service.
    const connection = ctx.get('connection');
    if (connection?.trustedHosts !== undefined && connection.trustedHosts.length > 0) {
        return connection.trustedHosts;
    }
    const hosts = [];
    const argv = process.argv;
    for (let i = 0; i < argv.length; i++) {
        const arg = argv[i];
        if (arg === '--trusted-host' && argv[i + 1] !== undefined)
            hosts.push(argv[i + 1]);
        else if (argv[i]?.startsWith('--trusted-host='))
            hosts.push(arg.slice('--trusted-host='.length));
    }
    return hosts;
}
export function apply(ctx, config) {
    const resolved = resolveConfig(config, process.env);
    const logger = ctx.logger ?? { info() { }, warn() { } };
    logBoot(logger, {
        configured: isCloudflareConfigured(resolved),
        audienceCount: resolved.audiences.length,
        ordinary: resolved.ordinary,
        issuer: issuerOf(resolved),
    });
    const verifier = createJwtVerifier(resolved);
    installServerCompat(ctx, {
        config: resolved,
        verifier,
        getTrustedHosts: () => trustedHostsFrom(ctx),
    });
}
//# sourceMappingURL=index.js.map
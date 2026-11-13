/**
 * DSH 0.1.5-alpha.1 HTTP paths used by the JWT overlay.
 * Hardcoded so JWT / policy never import DSH packages.
 */
export declare const API_PATH = "/api";
/** Gateway multiplexed Remote stream WebSocket. */
export declare const REMOTE_STREAM_MUX_PATH = "/api/remote.mux";
/**
 * dsh-superagent mounts its management panel as one prefix route on the same
 * loopback web server. The panel has no authentication of its own, so behind a
 * tunnel it needs the same JWT gate the DSH API gets.
 */
export declare const ORCHESTRATOR_PATH = "/orchestrator";
export declare function rpcMethodFromUrl(url: string | undefined): string | undefined;
//# sourceMappingURL=api-path.d.ts.map
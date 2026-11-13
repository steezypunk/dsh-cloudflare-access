/**
 * DSH 0.1.5-alpha.1 HTTP paths used by the JWT overlay.
 * Hardcoded so JWT / policy never import DSH packages.
 */

export const API_PATH = '/api'

/** Gateway multiplexed Remote stream WebSocket. */
export const REMOTE_STREAM_MUX_PATH = `${API_PATH}/remote.mux`

/**
 * dsh-superagent mounts its management panel as one prefix route on the same
 * loopback web server. The panel has no authentication of its own, so behind a
 * tunnel it needs the same JWT gate the DSH API gets.
 */
export const ORCHESTRATOR_PATH = '/orchestrator'

export function rpcMethodFromUrl(url: string | undefined): string | undefined {
  if (url === undefined) return undefined
  let pathname: string
  try {
    pathname = new URL(url, 'http://dsh.internal').pathname
  } catch {
    return undefined
  }
  if (pathname === REMOTE_STREAM_MUX_PATH) return 'remote.mux'
  if (!pathname.startsWith(`${API_PATH}/`)) return undefined
  return pathname.slice(API_PATH.length + 1)
}

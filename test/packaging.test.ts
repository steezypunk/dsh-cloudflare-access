import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'

const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'))
const patch = readFileSync(new URL('../cordis.patch.yml', import.meta.url), 'utf8')
const client = readFileSync(new URL('../lib/client.js', import.meta.url), 'utf8')

describe('dsh plugin manifest', () => {
  it('declares an independently installable Host + Web bundle', () => {
    expect(pkg.dsh.bundle.patch).toBe('./cordis.patch.yml')
    expect(pkg.dsh.client.platform).toBe('web')
    expect(pkg.dsh.client.immediately).toBe(true)
    expect(pkg.dsh.client.inject).toContain('@deepseek-ai/dsh-client-connection')
    expect(pkg.exports['.'].default).toBe('./lib/index.js')
    expect(pkg.exports['./client'].default).toBe('./lib/client.js')
    expect(pkg.exports['./cordis.patch.yml']).toBe('./cordis.patch.yml')
    expect(pkg.files).toEqual(expect.arrayContaining(['lib', 'cordis.patch.yml', 'README.md', 'LICENSE']))
    expect(pkg.keywords).toContain('dsh-plugin')
    expect(pkg.publishConfig.access).toBe('public')
    expect(pkg.peerDependencies['@deepseek-ai/dsh-host-webserver']).toBe('0.2.0-rc.2')
    expect(pkg.peerDependencies['@deepseek-ai/dsh-client-connection']).toBe('0.2.0-rc.2')
    expect(pkg.peerDependencies['@deepseek-ai/dsh-host-apiproxy']).toBeUndefined()
  })

  it('inserts the installed package name as a stable bundle row', () => {
    expect(patch).toMatch(/id:\s*cloudflare-access/)
    expect(patch).toContain(`name: ${pkg.name}`)
  })

  it('ships a Harness-compatible client factory', () => {
    expect(client).toContain('window.__ModuleLoader__.load')
    expect(client).toContain(JSON.stringify(pkg.name))
  })
})

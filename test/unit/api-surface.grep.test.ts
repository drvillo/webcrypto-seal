/**
 * Grep gate: package src/ must not contain product vocabulary.
 * Historical domain strings (1bridge-*) / lsk-wrap / wire field vaultId are allowed.
 */
import { readdirSync, readFileSync, statSync } from 'node:fs'
import { dirname, join, relative } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'

const srcRoot = join(dirname(fileURLToPath(import.meta.url)), '../../src')

const FORBIDDEN = [
  'documentRequest',
  'shareLink',
  'signingRequest',
  'OwnerKeyKind',
  'deriveVaultKek',
  'document-dek',
  'signing-lsk',
  'CONTEXT_KINDS',
]

function walkTsFiles(dir: string): string[] {
  const out: string[] = []
  for (const name of readdirSync(dir)) {
    const path = join(dir, name)
    if (statSync(path).isDirectory()) out.push(...walkTsFiles(path))
    else if (name.endsWith('.ts')) out.push(path)
  }
  return out
}

describe('api-surface grep gate', () => {
  it('src/ contains none of the forbidden product identifiers', () => {
    const hits: string[] = []
    for (const file of walkTsFiles(srcRoot)) {
      const text = readFileSync(file, 'utf8')
      for (const needle of FORBIDDEN) {
        if (text.includes(needle)) {
          hits.push(`${relative(srcRoot, file)}: ${needle}`)
        }
      }
    }
    expect(hits).toEqual([])
  })
})

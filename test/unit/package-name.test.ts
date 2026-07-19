import { describe, expect, it } from 'vitest'
import { PACKAGE_NAME } from '../../src/index'

describe('package stub', () => {
  it('exports the locked package name', () => {
    expect(PACKAGE_NAME).toBe('@drvillo/webcrypto-seal')
  })
})

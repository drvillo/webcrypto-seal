import { describe, expect, it } from 'vitest'
import { PACKAGE_NAME } from '../../../src/index'

describe('node runtime smoke', () => {
  it('loads the package stub under Node', () => {
    expect(PACKAGE_NAME).toBe('@drvillo/webcrypto-seal')
  })
})

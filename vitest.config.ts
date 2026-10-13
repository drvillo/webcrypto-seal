import { defineConfig } from 'vitest/config'

const [nodeMajor, nodeMinor, nodePatch] = process.versions.node
  .split('.')
  .map(Number)
const supportsJsdom30 =
  nodeMajor >= 26 ||
  (nodeMajor === 24 && (nodeMinor > 15 || (nodeMinor === 15 && nodePatch >= 0))) ||
  (nodeMajor === 22 && (nodeMinor > 22 || (nodeMinor === 22 && nodePatch >= 2)))
const domEnvironment = supportsJsdom30 ? 'jsdom' : 'happy-dom'

export default defineConfig({
  test: {
    globals: true,
    include: ['test/unit/**/*.test.ts'],
    exclude: ['node_modules/**'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html'],
    },
    projects: [
      {
        test: {
          // jsdom 30 supports Node ^22.22.2, ^24.15.0, and >=26. Keep the
          // package's Node 20 floor (and unsupported interim minors) on happy-dom.
          name: domEnvironment,
          environment: domEnvironment,
          include: ['test/unit/**/*.test.ts'],
          exclude: [
            'test/unit/node/**',
            'test/unit/node-offline.test.ts',
            'node_modules/**',
          ],
        },
      },
      {
        test: {
          name: 'node',
          environment: 'node',
          include: ['test/unit/node/**/*.test.ts', 'test/unit/node-offline.test.ts'],
          exclude: ['node_modules/**'],
        },
      },
    ],
  },
})

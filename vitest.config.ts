import { defineConfig } from 'vitest/config'

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
          name: 'jsdom',
          environment: 'jsdom',
          include: ['test/unit/**/*.test.ts'],
          exclude: ['test/unit/node/**', 'node_modules/**'],
        },
      },
      {
        test: {
          name: 'node',
          environment: 'node',
          include: ['test/unit/node/**/*.test.ts'],
          exclude: ['node_modules/**'],
        },
      },
    ],
  },
})

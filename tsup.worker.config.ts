import { defineConfig } from 'tsup'

/**
 * Separate worker build: bundles @noble/hashes so the module Worker has no bare imports.
 * Runs after the main tsup clean (see package.json "build" script).
 */
export default defineConfig({
  entry: {
    'argon2-worker/worker': 'src/argon2-worker/worker.ts',
  },
  format: ['esm'],
  dts: false,
  splitting: false,
  sourcemap: true,
  clean: false,
  treeshake: true,
  minify: false,
  target: 'es2020',
  noExternal: [/@noble\/hashes/],
})

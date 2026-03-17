import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    include: ['tests/**/*.test.ts'],
    // Use forks pool to avoid SIGSEGV from KuzuDB native module cleanup
    pool: 'forks',
    coverage: {
      provider: 'v8',
      include: ['src/**/*.ts'],
    },
  },
});

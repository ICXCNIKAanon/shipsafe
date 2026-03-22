import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    include: ['tests/**/*.test.ts'],
    pool: 'forks',
    poolOptions: {
      forks: {
        maxForks: 2, // Limit workers to prevent memory exhaustion (patterns.ts is 13k+ lines)
      },
    },
    coverage: {
      provider: 'v8',
      include: ['src/**/*.ts'],
    },
  },
});

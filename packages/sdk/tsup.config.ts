import { defineConfig } from 'tsup';

export default defineConfig([
  // Main SDK entry
  {
    entry: ['src/index.ts'],
    format: ['cjs', 'esm'],
    dts: true,
    clean: true,
    sourcemap: true,
    outDir: 'dist',
  },
  // React entry
  {
    entry: ['src/react/index.ts'],
    format: ['cjs', 'esm'],
    dts: true,
    clean: false,
    sourcemap: true,
    outDir: 'dist/react',
    external: ['react'],
  },
]);

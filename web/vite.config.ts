import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { defineConfig, type Plugin } from "vitest/config";

/**
 * Writes the npm packages whose code is in the bundle to `dist-packages.json` (outside
 * `dist/`, so it is not served). scripts/notices.mjs lists exactly these, so the notices
 * match what ships rather than what is installed.
 */
function bundledPackages(): Plugin {
  return {
    name: "thadam-bundled-packages",
    apply: "build",
    generateBundle(_options, bundle) {
      const names = new Set<string>();
      for (const out of Object.values(bundle)) {
        if (out.type !== "chunk") continue;
        for (const id of Object.keys(out.modules)) {
          const m = /.*node_modules\/((?:@[^/]+\/)?[^/]+)\//.exec(id);
          if (m?.[1] !== undefined) names.add(m[1]);
        }
      }
      writeFileSync(
        fileURLToPath(new URL("./dist-packages.json", import.meta.url)),
        JSON.stringify([...names].sort(), null, 2) + "\n",
      );
    },
  };
}

export default defineConfig({
  // JSX through Vite's built-in transform; no React plugin (ADR-008 Decision 13).
  esbuild: { jsx: "automatic" },
  plugins: [bundledPackages()],
  build: { outDir: "dist", emptyOutDir: true, sourcemap: false, target: "es2023" },
  server: {
    // Development only: the API on its default port serves /api (ADR-008 Decision 1).
    proxy: { "/api": "http://127.0.0.1:7341" },
  },
  test: { environment: "jsdom", globals: true, include: ["src/**/*.test.{ts,tsx}"] },
});

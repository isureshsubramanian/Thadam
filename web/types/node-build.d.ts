// The two Node functions vite.config.ts uses, declared here instead of adding @types/node
// (one fewer dependency). Build configuration only; never part of the dashboard bundle.
declare module "node:fs" {
  export function writeFileSync(path: string, data: string): void;
}
declare module "node:url" {
  export function fileURLToPath(url: URL): string;
}

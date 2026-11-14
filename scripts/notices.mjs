#!/usr/bin/env node
// Licence check and notices for the API's NuGet packages (ADR-008 Dependencies).
//
//   node scripts/notices.mjs <cargo-about output> > THIRD-PARTY-NOTICES.txt
//
// Appends a .NET section to the Rust section that cargo-about generates. Every package of a
// shipped project (api/src) must have a licence on deny.toml's allow list (or a recorded
// exception) and a licence text: from the package itself, or from scripts/notices-input.
// Test-only packages (api/tests) are licence-checked but not listed. Fails, naming the
// package, when anything is missing. No network access; no npm packages.

import { execFileSync } from "node:child_process";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

const root = new URL("..", import.meta.url).pathname;
const inputDir = join(root, "scripts/notices-input");

function fail(message) {
  process.stderr.write(`notices: ${message}\n`);
  process.exit(1);
}

/** The licence allow list, read from deny.toml so Rust and .NET share one policy. */
function allowList() {
  const toml = readFileSync(join(root, "deny.toml"), "utf8");
  const m = toml.match(/^allow\s*=\s*\[([^\]]*)\]/m);
  if (!m) fail("no allow list in deny.toml");
  return new Set([...m[1].matchAll(/"([^"]+)"/g)].map((x) => x[1]));
}

function dotnet(args) {
  return execFileSync("dotnet", args, {
    cwd: join(root, "api"),
    encoding: "utf8",
    env: { ...process.env, DOTNET_CLI_TELEMETRY_OPTOUT: "1", DOTNET_NOLOGO: "1" },
  });
}

/** Packages per project kind: shipped (api/src) and test-only (api/tests). */
function packages() {
  const listed = JSON.parse(
    dotnet(["list", "Thadam.slnx", "package", "--include-transitive", "--format", "json"]),
  );
  const shipped = new Map();
  const testOnly = new Map();
  for (const project of listed.projects ?? []) {
    const isTest = /[/\\]api[/\\]tests[/\\]/.test(project.path);
    for (const fw of project.frameworks ?? []) {
      for (const p of [...(fw.topLevelPackages ?? []), ...(fw.transitivePackages ?? [])]) {
        (isTest ? testOnly : shipped).set(`${p.id}@${p.resolvedVersion}`, {
          id: p.id,
          version: p.resolvedVersion,
        });
      }
    }
  }
  for (const key of shipped.keys()) testOnly.delete(key);
  const order = (m) => [...m.values()].sort((a, b) => a.id.localeCompare(b.id));
  return { shipped: order(shipped), testOnly: order(testOnly) };
}

function packageFolder(id, version) {
  const out = dotnet(["nuget", "locals", "global-packages", "--list"]);
  const base = out.slice(out.indexOf(":") + 1).trim();
  const dir = join(base, id.toLowerCase(), version.toLowerCase());
  if (!existsSync(dir)) fail(`${id} ${version}: not restored (run dotnet restore)`);
  return dir;
}

/** The licence the package declares: an SPDX expression, or a file inside the package. */
function declared(dir) {
  const nuspec = readdirSync(dir).find((f) => f.endsWith(".nuspec"));
  const xml = readFileSync(join(dir, nuspec), "utf8");
  const m = xml.match(/<license\s+type="(expression|file)"[^>]*>([^<]+)<\/license>/);
  const copyright = (xml.match(/<copyright>([^<]*)<\/copyright>/) ?? [])[1] ?? "";
  if (!m) return { kind: "none", copyright };
  return { kind: m[1], value: m[2].trim(), copyright };
}

function licenceOk(expression, allowed) {
  // Plain ids and OR-expressions only; anything else needs a person to read it.
  return expression.split(/\s+OR\s+/).some((id) => allowed.has(id.trim()));
}

function matches(pattern, id) {
  return pattern.endsWith(".*") ? id.startsWith(pattern.slice(0, -1)) : pattern === id;
}

function main() {
  const [aboutFile] = process.argv.slice(2);
  if (!aboutFile) fail("usage: node scripts/notices.mjs <cargo-about output>");
  const allowed = allowList();
  const input = JSON.parse(readFileSync(join(inputDir, "nuget.json"), "utf8"));
  const { shipped, testOnly } = packages();

  for (const p of testOnly) {
    const d = declared(packageFolder(p.id, p.version));
    if (d.kind !== "expression" || !licenceOk(d.value, allowed)) {
      fail(`${p.id} ${p.version} (test only): licence ${d.value ?? "not stated"} is not allowed`);
    }
  }

  const sections = [];
  for (const p of shipped) {
    const dir = packageFolder(p.id, p.version);
    const d = declared(dir);
    const exception = input.exceptions[p.id];
    let licence;
    let texts = [];
    if (exception) {
      licence = exception.licence;
      if (d.kind === "file") texts.push({ name: d.value, body: readFileSync(join(dir, d.value), "utf8") });
    } else if (d.kind === "expression" && licenceOk(d.value, allowed)) {
      licence = d.value;
      const entry = input.packages.find((e) => matches(e.match, p.id));
      if (!entry) fail(`${p.id} ${p.version}: no licence text in scripts/notices-input/nuget.json`);
      texts = entry.texts.map((name) => {
        const meta = input.texts[name];
        if (!meta) fail(`${name}: not described in nuget.json`);
        return {
          name: `${name} (from ${meta.source}, retrieved ${meta.retrieved})`,
          body: readFileSync(join(inputDir, "nuget", name), "utf8"),
        };
      });
    } else {
      fail(`${p.id} ${p.version}: licence ${d.value ?? "not stated"} is not allowed`);
    }
    sections.push({ ...p, licence, copyright: d.copyright, texts });
  }

  const rule = "=".repeat(80);
  let out = readFileSync(aboutFile, "utf8").replace(/\s*$/, "\n");
  out += `\n${rule}\n.NET PACKAGES (the API, api/)\n${rule}\n`;
  for (const s of sections) {
    out += `\n${"-".repeat(80)}\n${s.id} ${s.version}\nLicence: ${s.licence}\n`;
    if (s.copyright) out += `Copyright: ${s.copyright}\n`;
    for (const t of s.texts) out += `\n--- ${t.name}\n\n${t.body.replace(/\s*$/, "\n")}`;
  }
  process.stdout.write(out);
}

main();

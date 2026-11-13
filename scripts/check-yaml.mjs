// Well-formedness parse of the tracked plain-YAML set. kratos.yml and hydra.yml are
// templates, so they are excluded. Reads the git index; `yaml` resolves from portal/.
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("..", import.meta.url));
const YAML = createRequire(`${root}portal/package.json`)("yaml");

const files = execFileSync(
  "git",
  [
    "-C", root, "ls-files", "-z", "--",
    ".gitlab-ci.yml",
    "e2e/compose*.yml",
    "e2e/content/*.yaml",
    "e2e/content/apps/*.yaml",
    "deploy/example/*.yml",
    "deploy/example/content/*.yaml",
    "deploy/example/content/apps/*.yaml",
  ],
  { encoding: "utf8" },
).split("\0").filter(Boolean);

if (files.length === 0) {
  console.error("ERROR: 0 tracked plain-YAML files, nothing was parsed");
  process.exit(1);
}

let bad = 0;
for (const f of files) {
  try {
    const doc = YAML.parse(readFileSync(`${root}${f}`, "utf8"));
    const empty =
      doc === null ||
      doc === undefined ||
      (typeof doc === "object" && !Array.isArray(doc) && Object.keys(doc).length === 0) ||
      (Array.isArray(doc) && doc.length === 0);
    if (empty) {
      console.error(`FAIL: ${f} parsed to an empty document`);
      bad = 1;
    }
  } catch (e) {
    console.error(`FAIL: ${f}: ${e.message}`);
    bad = 1;
  }
}
if (!bad) console.log(`OK: ${files.length} tracked YAML files parse to non-empty documents`);
process.exit(bad);

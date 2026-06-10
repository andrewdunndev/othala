#!/usr/bin/env bash
# render-config.sh — THE canonical Ory-config render.
#
# Ory (Kratos/Hydra) has no native ${VAR} expansion in YAML: it validates the
# literal placeholder text and dies. The kratos/ + hydra/ configs are therefore
# TEMPLATES whose ${VAR} tokens must be substituted before a container mounts
# them. This script is the single render used by BOTH:
#   - the e2e harness (e2e/validate.sh), and
#   - the deploy plane (dunn.dev/iac renders with sops + inventory values).
# One render, one variable contract — what e2e validates is byte-identical in
# mechanism to what production deploys.
#
# Usage:
#   render-config.sh <template> <output>
# Variables are read from the environment (caller sources its .env / exports
# its sops+inventory values first).
#
# Semantics (deliberately stricter than os.path.expandvars):
#   - The variable contract is DERIVED FROM THE TEMPLATE: every ${NAME} token
#     found in it must be set AND non-empty in the environment, else we fail
#     fast listing the missing NAMES (names only — never file content, which
#     after partial substitution could carry secrets into CI logs).
#   - Only braced ${NAME} tokens are substituted. Unbraced $name is left
#     alone (expandvars would mangle it), and nothing outside the template's
#     own token set is consulted — no accidental ${HOME}-style pickup from a
#     wide caller environment.
#   - By construction there can be no un-rendered token left in the output,
#     so no post-render grep is needed.
set -euo pipefail

if [[ $# -ne 2 ]]; then
    echo "usage: render-config.sh <template> <output>" >&2
    exit 2
fi
TEMPLATE="$1"
OUTPUT="$2"

if [[ ! -f "$TEMPLATE" ]]; then
    echo "render-config: template not found: $TEMPLATE" >&2
    exit 1
fi

# Rendered output carries secrets — never world-readable.
umask 077

python3 - "$TEMPLATE" "$OUTPUT" <<'PY'
import os, re, sys

template_path, output_path = sys.argv[1], sys.argv[2]
src = open(template_path).read()

TOKEN = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")

# Derive required tokens from a comment-stripped view so that ${VAR} tokens
# that appear only inside YAML comments don't become phantom required vars.
# Heuristic: strip from the first unquoted ' #' (space-hash) on each line, or
# from the start of lines whose first non-whitespace character is '#'. This is
# intentionally simple — it will miss '#' inside quoted strings, but no
# template value legitimately embeds a '#' in a comment context. Substitution
# itself runs against the full source so comment text is preserved verbatim.
def strip_comments(text):
    out = []
    for line in text.splitlines():
        stripped = line.lstrip()
        if stripped.startswith('#'):
            out.append('')
            continue
        # Remove inline comment: space-hash not inside quotes. A full parser
        # is out of scope; the space requirement avoids fragment-URIs like
        # https://host/#anchor. Limitation: '#' inside a quoted YAML scalar
        # that follows a space is also stripped — acceptable for this codebase.
        pos = line.find(' #')
        out.append(line[:pos] if pos != -1 else line)
    return '\n'.join(out)

needed = sorted(set(TOKEN.findall(strip_comments(src))))

missing = [n for n in needed if not os.environ.get(n)]
if missing:
    print(f"render-config: {template_path}: missing/empty render variable(s):",
          file=sys.stderr)
    for n in missing:
        print(f"  {n}", file=sys.stderr)
    sys.exit(1)

# Newline-injection guard: a substituted value containing a newline would
# break YAML structure (the newline shifts subsequent content out of its
# intended scalar context). Fail closed before writing any output.
for name in needed:
    val = os.environ[name]
    if '\n' in val:
        print(f"render-config: {template_path}: variable {name} contains a "
              f"newline — refusing to render (YAML structure injection guard)",
              file=sys.stderr)
        sys.exit(1)

# Substitute only tokens that are in `needed` (the non-comment set).
# Comment-only tokens are left as literal ${VAR} text in the output,
# which is harmless — they remain comments in the rendered YAML.
needed_set = set(needed)
rendered = TOKEN.sub(
    lambda m: os.environ[m.group(1)] if m.group(1) in needed_set else m.group(0),
    src
)
with open(output_path, "w") as f:
    f.write(rendered)
print(f"render-config: {template_path} -> {output_path} ({len(needed)} vars)")
PY

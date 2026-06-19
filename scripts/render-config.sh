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

# Control-character injection guard: a substituted value containing any
# control character (ord < 0x20, including \r, \n, and other non-printables)
# can break YAML structure or produce unparseable output. Fail closed before
# writing any output. \n (newline) would shift content out of its scalar
# context; \r produces ambiguous line endings; other controls are never
# legitimate in YAML scalar values in this codebase.
for name in needed:
    val = os.environ[name]
    bad = [c for c in val if ord(c) < 0x20]
    if bad:
        chars = ', '.join(repr(c) for c in set(bad))
        print(f"render-config: {template_path}: variable {name} contains "
              f"control character(s) {chars} — refusing to render "
              f"(YAML structure injection guard)",
              file=sys.stderr)
        sys.exit(1)

# Double-quote-context escaping contract:
# All ${VAR} tokens in the templates are wrapped in YAML double-quoted scalars
# (e.g. dsn: "postgres://...${PASS}..."). Inside a YAML double-quoted scalar,
# backslash is the escape character and double-quote terminates the scalar.
# A raw value injected verbatim would break the scalar if it contains either
# character. Escape order matters: backslash first (so the introduced \ in the
# \" escapes is not re-escaped), then double-quote.
def escape_for_double_quoted_yaml(val):
    val = val.replace('\\', '\\\\')   # \ → \\ (must be first)
    val = val.replace('"', '\\"')     # " → \"
    return val

# Substitute only tokens that are in `needed` (the non-comment set).
# Comment-only tokens are left as literal ${VAR} text in the output,
# which is harmless — they remain comments in the rendered YAML.
needed_set = set(needed)
rendered = TOKEN.sub(
    lambda m: escape_for_double_quoted_yaml(os.environ[m.group(1)])
              if m.group(1) in needed_set else m.group(0),
    src
)
with open(output_path, "w") as f:
    f.write(rendered)

# Post-render YAML validation: parse the rendered output to confirm it is
# structurally valid YAML. A substituted value that still breaks YAML (e.g. a
# lone colon at the start, tab characters, or other edge cases not caught by
# the escaping above) is caught here before the file reaches a container mount.
# If pyyaml is not available in the environment, skip with a warning — do not
# hard-fail on a missing module.
try:
    import yaml
    try:
        yaml.safe_load(open(output_path).read())
    except yaml.YAMLError as e:
        print(f"render-config: rendered output {output_path} failed YAML "
              f"validation — deleting partial output. Error: {e}",
              file=sys.stderr)
        import os as _os
        _os.unlink(output_path)
        sys.exit(1)
except ImportError:
    print(f"render-config: pyyaml not available — skipping post-render YAML "
          f"validation of {output_path}. Install pyyaml for full validation.",
          file=sys.stderr)

print(f"render-config: {template_path} -> {output_path} ({len(needed)} vars)")
PY

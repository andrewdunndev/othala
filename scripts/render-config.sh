#!/usr/bin/env bash
# render-config.sh: the Ory-config render shared by e2e/validate.sh and the deploy plane.
# Usage: render-config.sh <template> <output>, variables from the environment. Every ${NAME}
# left after #@if resolution and comment stripping must be SET (names-only error); exported-
# empty is allowed (OTHALA_OTLP_PROVIDER="" disables tracing). #@if NAME ... #@endif keeps the
# block when NAME is non-empty and drops it otherwise (Ory v26 rejects a half-populated block).
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
IF_RE = re.compile(r"^\s*#@if\s+([A-Za-z_][A-Za-z0-9_]*)\s*$")
ENDIF_RE = re.compile(r"^\s*#@endif\s*$")


# Resolve #@if blocks first so tokens only inside a dropped block are not required. Blocks do not nest.
def resolve_conditionals(text):
    out = []
    gate = None  # active gating var name, or None when outside a block
    keep = True  # whether the active block's body should be kept
    for lineno, line in enumerate(text.splitlines(), 1):
        m_if = IF_RE.match(line)
        m_endif = ENDIF_RE.match(line)
        if m_if:
            if gate is not None:
                print(f"render-config: {template_path}: nested #@if at line "
                      f"{lineno} (block '{gate}' still open) — not supported",
                      file=sys.stderr)
                sys.exit(1)
            gate = m_if.group(1)
            keep = bool(os.environ.get(gate, ""))
            continue  # drop the fence line itself
        if m_endif:
            if gate is None:
                print(f"render-config: {template_path}: #@endif without a "
                      f"matching #@if at line {lineno}", file=sys.stderr)
                sys.exit(1)
            gate = None
            keep = True
            continue  # drop the fence line itself
        if gate is None or keep:
            out.append(line)
    if gate is not None:
        print(f"render-config: {template_path}: unterminated #@if '{gate}' "
              f"(missing #@endif)", file=sys.stderr)
        sys.exit(1)
    result = '\n'.join(out)
    if text.endswith('\n'):
        result += '\n'
    return result


src = resolve_conditionals(src)

# Derive required tokens from a comment-stripped view so ${VAR} inside comments is not a phantom
# requirement. Simple heuristic (misses '#' inside quoted strings); substitution uses the full source.
def strip_comments(text):
    out = []
    for line in text.splitlines():
        stripped = line.lstrip()
        if stripped.startswith('#'):
            out.append('')
            continue
        # Strip an inline comment (space-hash, so fragment URIs survive).
        pos = line.find(' #')
        out.append(line[:pos] if pos != -1 else line)
    return '\n'.join(out)

needed = sorted(set(TOKEN.findall(strip_comments(src))))

missing = [n for n in needed if n not in os.environ]
if missing:
    print(f"render-config: {template_path}: missing render variable(s):",
          file=sys.stderr)
    for n in missing:
        print(f"  {n}", file=sys.stderr)
    sys.exit(1)

# Control-character guard: fail closed before writing output (a newline or CR breaks scalars).
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

# All tokens sit in YAML double-quoted scalars: escape backslash first, then double-quote.
def escape_for_double_quoted_yaml(val):
    val = val.replace('\\', '\\\\')   # \ → \\ (must be first)
    val = val.replace('"', '\\"')     # " → \"
    return val

# Substitute only the needed (non-comment) tokens; comment-only tokens stay literal.
needed_set = set(needed)
rendered = TOKEN.sub(
    lambda m: escape_for_double_quoted_yaml(os.environ[m.group(1)])
              if m.group(1) in needed_set else m.group(0),
    src
)
with open(output_path, "w") as f:
    f.write(rendered)

# Post-render YAML parse catches values that still break YAML; skipped with a warning if
# pyyaml is missing.
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

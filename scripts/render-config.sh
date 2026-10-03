#!/usr/bin/env bash
# render-config.sh: the Ory-config render shared by e2e/validate.sh and the deploy plane.
# Usage: render-config.sh <template> <output>, variables from the environment. Every ${NAME}
# left after #@if resolution (and, in YAML, comment stripping) must be SET (names-only error).
# #@if NAME ... #@endif keeps the block when NAME is non-empty and drops it otherwise (Ory
# rejects a half-populated tracing block). Values are escaped for YAML double-quoted scalars,
# for HTML in *.html.gotmpl, and land verbatim in other *.gotmpl (Kratos mail templates).
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
import html, os, re, sys

template_path, output_path = sys.argv[1], sys.argv[2]
src = open(template_path).read()
mode = "html" if template_path.endswith(".html.gotmpl") else "text" if template_path.endswith(".gotmpl") else "yaml"

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

# YAML comments may name ${VAR} without requiring it; the heuristic misses '#' inside quoted strings.
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

needed = sorted(set(TOKEN.findall(strip_comments(src) if mode == "yaml" else src)))

missing = [n for n in needed if n not in os.environ]
if missing:
    print(f"render-config: {template_path}: missing render variable(s):",
          file=sys.stderr)
    for n in missing:
        print(f"  {n}", file=sys.stderr)
    sys.exit(1)

# The Ory admin binds have no default: an empty value is refused (a wildcard is the isolated e2e network's choice).
for name in ("KRATOS_ADMIN_BIND_HOST", "HYDRA_ADMIN_BIND_HOST"):
    if name in needed and not os.environ[name].strip():
        print(f"render-config: {template_path}: {name} must not be empty "
              f"— refusing to render", file=sys.stderr)
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
    # Kratos parses mail templates as Go templates: a delimiter in a value would inject an action.
    if mode != "yaml" and ("{{" in val or "}}" in val):
        print(f"render-config: {template_path}: variable {name} contains a "
              f"template delimiter — refusing to render", file=sys.stderr)
        sys.exit(1)

# YAML tokens sit in double-quoted scalars: escape backslash first, then double-quote.
def escape_for_double_quoted_yaml(val):
    return val.replace('\\', '\\\\').replace('"', '\\"')

escape = {"yaml": escape_for_double_quoted_yaml, "html": html.escape, "text": str}[mode]
needed_set = set(needed)
rendered = TOKEN.sub(
    lambda m: escape(os.environ[m.group(1)]) if m.group(1) in needed_set else m.group(0),
    src
)
with open(output_path, "w") as f:
    f.write(rendered)

if mode == "yaml":
    try:
        import yaml
        try:
            yaml.safe_load(rendered)
        except yaml.YAMLError as e:
            print(f"render-config: rendered output {output_path} failed YAML "
                  f"validation — deleting partial output. Error: {e}",
                  file=sys.stderr)
            os.unlink(output_path)
            sys.exit(1)
    except ImportError:
        print(f"render-config: pyyaml not available — skipping post-render YAML "
              f"validation of {output_path}. Install pyyaml for full validation.",
              file=sys.stderr)

print(f"render-config: {template_path} -> {output_path} ({len(needed)} vars)")
PY

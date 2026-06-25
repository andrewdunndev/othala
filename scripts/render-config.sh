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
#     found in it must be SET in the environment, else we fail fast listing the
#     missing NAMES (names only — never file content, which after partial
#     substitution could carry secrets into CI logs). An exported-but-EMPTY
#     value is permitted on purpose: it is a valid intentional signal (e.g.
#     OTHALA_OTLP_PROVIDER="" disables Ory tracing — the tracer no-ops on an
#     empty provider). Only a wholly UNSET var is a contract violation. The
#     empty value is still run through the control-char + escaping guards below,
#     so an empty string renders as an empty YAML scalar, never a broken one.
#   - Only braced ${NAME} tokens are substituted. Unbraced $name is left
#     alone (expandvars would mangle it), and nothing outside the template's
#     own token set is consulted — no accidental ${HOME}-style pickup from a
#     wide caller environment.
#   - By construction there can be no un-rendered token left in the output,
#     so no post-render grep is needed.
#
# Conditional blocks (#@if / #@endif):
#   - A region fenced by a line whose only content is `#@if NAME` and a closing
#     `#@endif` line is INCLUDED verbatim (fence lines removed) when env var
#     NAME is set and NON-EMPTY, and DROPPED ENTIRELY when NAME is unset or
#     empty. This exists for Ory v26's schema, which rejects a present-but-
#     half-populated optional block: the `tracing:` block must be wholly ABSENT
#     when tracing is disabled (OTHALA_OTLP_PROVIDER="") but wholly PRESENT and
#     valid when enabled (provider="otel"). A simple empty-scalar render is not
#     enough — the schema validates the block's $ref the moment the key exists.
#   - Conditional stripping happens BEFORE token derivation, so ${VAR} tokens
#     that live ONLY inside a dropped block are not required in the environment.
#     (When tracing is off, OTHALA_OTLP_ENDPOINT/ENVIRONMENT need not be set.)
#   - The gating NAME on an #@if is itself a required-when-present signal, not a
#     substituted token; it is matched against the environment directly.
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


# Resolve conditional blocks FIRST, before token derivation, so tokens that
# live only inside a dropped block are not part of the required contract.
# `#@if NAME` ... `#@endif`: keep the inner lines (drop the two fence lines)
# when NAME is set and non-empty; drop the whole region (fences + body) when
# NAME is unset or empty. Blocks do not nest (a nested #@if inside an open
# block is a template authoring error and is rejected).
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
    # Preserve a trailing newline if the source had one.
    result = '\n'.join(out)
    if text.endswith('\n'):
        result += '\n'
    return result


src = resolve_conditionals(src)

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

# UNSET is the contract violation, not empty. An exported empty value (e.g.
# OTHALA_OTLP_PROVIDER="") is a deliberate "off" signal and renders as an empty
# YAML scalar (the control-char + escaping guards below still apply to it).
missing = [n for n in needed if n not in os.environ]
if missing:
    print(f"render-config: {template_path}: missing render variable(s):",
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

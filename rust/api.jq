# The public surface of a crate from rustdoc JSON: one line per item, item attribute, public field, method with its
# signature, variant and trait impl (blanket and auto impls omitted).
.index as $ix
| def kind: .inner | keys[0];
  def name_of($id): $ix[($id|tostring)].name;
  def ty:
    def gargs: if . == null then ""
      elif has("angle_bracketed") then
        [ (.angle_bracketed.args[] | if has("type") then (.type | ty) elif has("const") then (.const.expr // tojson) elif has("lifetime") then .lifetime else tojson end),
          (.angle_bracketed.constraints[]? | "\(.name) = \(.binding.equality.type | ty)") ]
        | if length == 0 then "" else "<\(join(", "))>" end
      elif has("parenthesized") then
        "(\(.parenthesized.inputs | map(ty) | join(", ")))" + (if .parenthesized.output then " -> \(.parenthesized.output | ty)" else "" end)
      else tojson end;
    if . == null then "()"
    elif has("trait_bound") then (.trait_bound.trait | "\(.path)\(.args | gargs)")
    elif has("outlives") then .outlives
    elif has("primitive") then .primitive
    elif has("generic") then .generic
    elif has("resolved_path") then (.resolved_path | "\(.path)\(.args | gargs)")
    elif has("borrowed_ref") then (.borrowed_ref | "&\(if .lifetime then "\(.lifetime) " else "" end)\(if .is_mutable then "mut " else "" end)\(.type | ty)")
    elif has("tuple") then "(\(.tuple | map(ty) | join(", ")))"
    elif has("slice") then "[\(.slice | ty)]"
    elif has("array") then "[\(.array.type | ty); \(.array.len)]"
    elif has("impl_trait") then "impl \(.impl_trait | map(ty) | join(" + "))"
    elif has("dyn_trait") then "dyn \(.dyn_trait.traits | map(.trait | "\(.path)\(.args | gargs)") | join(" + "))"
    elif has("qualified_path") then (.qualified_path | if (.trait.path // "") == "" then "\(.self_type | ty)::\(.name)" else "<\(.self_type | ty) as \(.trait.path)>::\(.name)" end)
    else tojson end;
  def bound: ty;
  def params: [ .params[] | select(.kind.type.is_synthetic != true)
      | if .kind | has("type") then "\(.name)\(if (.kind.type.bounds | length) > 0 then ": \(.kind.type.bounds | map(bound) | join(" + "))" else "" end)"
        elif .kind | has("const") then "const \(.name): \(.kind.const.type | ty)"
        else .name end ]
    | if length == 0 then "" else "<\(join(", "))>" end;
  def sig: .inner.function
    | "\(if .header.is_const then "const " else "" end)fn\(.generics | params)(\(.sig.inputs | map("\(.[0]): \(.[1] | ty)") | join(", ")))"
      + (if .sig.output then " -> \(.sig.output | ty)" else "" end);
  ([ $ix[] | select(kind == "impl") | .inner.impl.items[] ] + [ $ix[] | select(kind == "trait") | .inner.trait.items[] ]
   | map(tostring)) as $members
  | [ $ix[] | select(.crate_id == 0 and .visibility == "public" and .name != null)
    | select(kind | IN("struct", "enum", "trait", "function", "constant", "type_alias", "macro"))
    | select((.id | tostring) as $id | $members | index([$id]) | not)
    | . as $item
    | if kind == "function" then "function \(.name) \(sig)"
      elif kind == "constant" then "constant \(.name): \(.inner.constant.type | ty) = \(.inner.constant.const.expr)"
      else "\(kind) \(.name)" end,
      ( .attrs[]? | if type == "object" then keys[0] | select(. != "other") else . end | "attr \($item.name) \(.)" ),
      ( (.inner.struct.kind? | objects | (.plain.fields[]?, (.tuple[]? | select(. != null))))
        | $ix[(.|tostring)] | select(.visibility == "public") | "field \($item.name)::\(.name): \(.inner.struct_field | ty)" ),
      ( .inner.enum.variants[]? | $ix[(.|tostring)] as $v
        | "variant \($item.name)::\($v.name)",
          ( ($v.inner.variant.kind | objects | (.struct.fields[]?, .plain.fields[]?, (.tuple[]? | select(. != null))))
            | "field \($item.name)::\($v.name)::\(name_of(.)): \($ix[(.|tostring)].inner.struct_field | ty)" ) ),
      ( .inner.trait.items[]? | $ix[(.|tostring)] | "trait_item \($item.name)::\(.name)\(if kind == "function" then " \(sig)" else "" end)" ),
      ( (.inner.struct.impls // .inner.enum.impls // [])[] | $ix[(.|tostring)].inner.impl
        | select(.is_synthetic | not) | select(.blanket_impl == null)
        | if .trait == null
          then (.items[] | $ix[(.|tostring)] | select(.visibility == "public") | "method \($item.name)::\(.name) \(sig)")
          else "impl \(.trait.path) for \($item.name)"
          end )
  ] | unique | .[]

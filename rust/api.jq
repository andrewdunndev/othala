# The public surface of a crate from rustdoc JSON: items, variants, methods and trait impls (blanket and auto impls omitted).
.index as $ix
| def kind: .inner | keys[0];
  def name_of($id): $ix[($id|tostring)].name;
  [ $ix[] | select(.crate_id == 0 and .visibility == "public" and .name != null)
    | select(kind | IN("struct", "enum", "trait", "function", "constant", "type_alias"))
    | . as $item
    | "pub \(kind) \(.name)",
      ( .inner.enum.variants[]? | "pub \($item.name)::\(name_of(.))" ),
      ( .inner.trait.items[]? | "pub \($item.name)::\(name_of(.))" ),
      ( (.inner.struct.impls // .inner.enum.impls // [])[] | $ix[(.|tostring)].inner.impl
        | select(.is_synthetic | not) | select(.blanket_impl == null)
        | if .trait == null
          then (.items[] | $ix[(.|tostring)] | select(.visibility == "public") | "pub \($item.name)::\(.name)")
          else "impl \(.trait.path) for \($item.name)"
          end )
  ] | unique | .[]

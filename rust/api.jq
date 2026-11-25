# The public surface of a crate from rustdoc JSON, one line per item, method, variant and trait impl (blanket and auto impls omitted).
.index as $ix
| def kind: .inner | keys[0];
  def name_of($id): $ix[($id|tostring)].name;
  ([ $ix[] | select(kind == "impl") | .inner.impl.items[] ] + [ $ix[] | select(kind == "trait") | .inner.trait.items[] ]
   | map(tostring)) as $members
  | [ $ix[] | select(.crate_id == 0 and .visibility == "public" and .name != null)
    | select(kind | IN("struct", "enum", "trait", "function", "constant", "type_alias", "macro"))
    | select((.id | tostring) as $id | $members | index([$id]) | not)
    | . as $item
    | "\(kind) \(.name)",
      ( .inner.enum.variants[]? | "variant \($item.name)::\(name_of(.))" ),
      ( .inner.trait.items[]? | "trait_item \($item.name)::\(name_of(.))" ),
      ( (.inner.struct.impls // .inner.enum.impls // [])[] | $ix[(.|tostring)].inner.impl
        | select(.is_synthetic | not) | select(.blanket_impl == null)
        | if .trait == null
          then (.items[] | $ix[(.|tostring)] | select(.visibility == "public") | "method \($item.name)::\(.name)")
          else "impl \(.trait.path) for \($item.name)"
          end )
  ] | unique | .[]

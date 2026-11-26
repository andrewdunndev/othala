# R-j: every public item of a crate that names an item of the `expose` crate (a use, a glob, an extern crate, a supertrait, a dyn or
# generic bound, a signature), one line each; base's impls of the read for Secret and SecretBytes are the only exceptions.
(.index[.root | tostring].name) as $me
| ([ .external_crates | to_entries[] | select(.value.name == "expose") | .key | tonumber ]) as $cids
| ([ .paths | to_entries[] | select(.value.crate_id as $c | $cids | index($c)) | .key | tonumber ]) as $ids
| .index[] | select(.crate_id == 0)
| . as $it
| select(
    (.inner | has("extern_crate")) and .inner.extern_crate.name == "expose" and .visibility == "public"
    or ([ .inner | .. | objects | select(has("id")) | .id ] | any(. as $i | $ids | index($i)))
  )
| select(
    ($me == "base" and (.inner | has("impl"))
      and ((.inner.impl.trait.id // -1) as $t | $ids | index($t))
      and (.inner.impl.for.resolved_path.path | IN("Secret", "SecretBytes"))) | not)
| "\($me): public \(.inner | keys[0]) \(.inner.use.source // .inner.extern_crate.name // .name // "<unnamed>") (\(.inner.use.name // "")) names the expose crate"

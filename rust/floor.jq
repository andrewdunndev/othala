# the one rule for a mutants floor: a crate with a mutants key names a non-negative integer, spelled as digits only
def floor_ok: if has("mutants") then (.mutants | type == "object") and (.mutants.floor | tojson | test("^[0-9]+$")) else true end;

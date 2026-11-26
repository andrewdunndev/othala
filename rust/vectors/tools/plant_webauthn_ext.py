#!/usr/bin/env python3
"""Plant for tools/check_webauthn_ext.mjs: the generated vectors plus one TPM case whose only fault is ES256 over a P-384 AIK.

usage: python3 -I plant_webauthn_ext.py <out-dir>
The statement signature verifies under SHA-256, so the checker must name the alg and key mismatch, not a signature fault.
Licence: MIT OR Apache-2.0.
"""
import json, os, runpy, sys

here = os.path.dirname(os.path.abspath(__file__))
out = sys.argv[1]
g = runpy.run_path(os.path.join(here, "derive_webauthn_ext.py"), run_name="plant", init_globals={})
plant = g["tpm_case"]("tpm-plant-es256-p384-aik", "(plant: ES256 with a P-384 AIK)", g["NO"], alg=-7, aik=g["aik_cert"](g["TPM_AIK_P384"], "Derived TPM AIK P384 Plant"))
path = os.path.join(out, "webauthn-rp-derived", "attestation.json")
doc = json.load(open(path))
doc["cases"].append(plant)
json.dump(doc, open(path, "w"), indent=1)

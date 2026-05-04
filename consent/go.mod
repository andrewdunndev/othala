module dunn.dev/auth/consent

go 1.22

// One external dep: gopkg.in/yaml.v3 for parsing hydra/clients/*.yaml
// in v2 (per-app role manifests). All Hydra and Kratos calls remain
// hand-rolled net/http; we still don't pull in the Ory SDKs.
require gopkg.in/yaml.v3 v3.0.1

module dunn.dev/auth/consent

go 1.22

// No external deps in v1; all flow is plain net/http calls to Hydra and
// Kratos public APIs. We may add the official Ory client SDKs later if
// they're useful, but the API surface is small enough that hand-rolled
// HTTP keeps the dep tree minimal.

Grafana is the open-source observability dashboard for metrics, logs, and
traces. It signs users in over OIDC through its built-in **generic OAuth**
provider: the browser is redirected to the identity provider, comes back with
an authorization code, and Grafana exchanges it for an id_token.

The interesting part is role mapping. Grafana does not consume an OIDC `roles`
claim directly — instead it evaluates a JMESPath expression
(`role_attribute_path`) against the token to resolve a single Grafana role:
`Viewer`, `Editor`, `Admin`, or `GrafanaAdmin`. This fixture emits a
`grafana_role` array claim per identity group (admins map to `GrafanaAdmin`,
everyone else to `Viewer`) plus a `groups` claim, so a single sign-in carries
both the role decision and group membership. That makes Grafana the canonical
example of claim-driven authorization: change the group, change the role, no
per-user config on the app side.

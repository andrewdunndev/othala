# Architecture diagrams

Companion to `docs/architecture.md`. Use these when explaining the
approach to someone who has not read the spec.

## 1. System topology

Where the bytes go. Cloudflare is DNS only; carmine terminates TLS and
runs every auth-pod service.

```mermaid
flowchart TB
  user([User browser / app client])

  subgraph CF[Cloudflare]
    dns[DNS records<br/>gray cloud, no proxy]
  end

  subgraph Home[Home network]
    router[Home router<br/>port-forward 443]
  end

  subgraph Carmine[carmine host]
    envoy[Envoy<br/>L4 SNI router 80/443]

    subgraph AuthPod[auth pod]
      caddy[caddy-estate<br/>TLS + DNS-01]
      kratos[Kratos<br/>4433 public<br/>4434 admin]
      hydra[Hydra<br/>4444 public<br/>4445 admin]
      consent[Consent service<br/>4477]
      portal[Astro portal<br/>Node SSR 8080]
      courier[Kratos courier]
      pg[(Postgres<br/>kratos + hydra DBs)]
    end

    subgraph JellyfinPod[jellyfin pod]
      bridge[glauth-kratos<br/>LDAPS 636]
      jellyfin[Jellyfin]
    end

    subgraph AppPods[app pods]
      apps[12 apps<br/>caddy sidecar + container]
    end
  end

  user -->|DNS lookup| dns
  user -->|HTTPS 443| router
  router --> envoy
  envoy --> caddy
  envoy -.LDAPS off-path.-> bridge
  caddy --> kratos
  caddy --> hydra
  caddy --> consent
  caddy --> portal
  caddy --> apps
  portal --> kratos
  portal --> hydra
  consent --> hydra
  consent --> kratos
  kratos --> pg
  hydra --> pg
  courier --> pg
  bridge --> kratos
  jellyfin -->|localhost:636| bridge
```

## 2. Five integration patterns

Every family app falls into one of these. The pattern is fixed at
deploy time per app via the Caddyfile snippet it imports.

```mermaid
flowchart LR
  subgraph Native[OIDC native]
    n1[App] -->|redirect| n2[Hydra /oauth2/auth]
    n2 -->|code| n1
    n1 -->|exchange| n3[Hydra /oauth2/token]
    note1[keep, larder, listen, memory,<br/>vault, library, forge, observe]
  end

  subgraph LDAP[LDAP outpost]
    l1[Jellyfin] -->|BIND/SEARCH<br/>localhost:636| l2[glauth-kratos]
    l2 -->|public API| l3[Kratos]
    note2[cinema only]
  end

  subgraph FA[Forward auth]
    f1[Caddy] -->|forward_auth| f2[Kratos /sessions/whoami]
    f2 -->|200/401| f1
    f1 -->|allow/deny| f3[App]
    note3[tune, gather/*]
  end

  subgraph CC[Client credentials]
    c1[Caller] -->|Bearer| c2[Caddy]
    c2 -->|introspect| c3[Hydra]
    c2 -->|allow| c4[vLLM]
    note4[llm only]
  end

  subgraph WF[Custom OIDC + WebFinger]
    w1[Tailscale] -->|webfinger| w2[Astro endpoint]
    w2 -->|jrd+json| w1
    w1 -->|OIDC discovery| w3[Hydra]
    note5[Tailscale only]
  end
```

## 3. Login flow with passkey

The default family path. Password is the fallback, AAL2 step-up only
fires for `/admin/*`.

```mermaid
sequenceDiagram
  autonumber
  actor U as User
  participant B as Browser
  participant C as Caddy
  participant K as Kratos
  participant H as Hydra
  participant CS as Consent service
  participant A as App (e.g. keep)

  U->>A: visit keep.dunn.dev
  A->>B: 302 to Hydra /oauth2/auth
  B->>H: /oauth2/auth?client_id=keep
  H->>B: 302 to Kratos /self-service/login
  B->>K: GET login flow
  K->>B: render passkey challenge
  U->>B: tap passkey (WebAuthn rp.id=dunn.dev)
  B->>K: POST assertion
  K->>B: Set-Cookie ory_session<br/>302 back to Hydra
  B->>H: resume /oauth2/auth
  H->>CS: consent request<br/>(skip_consent for trusted client)
  CS->>K: getIdentity (admin API)
  CS->>CS: enforce access-keep group
  CS->>H: accept consent + claims
  H->>B: 302 with code
  B->>A: /callback?code=...
  A->>H: exchange code for tokens
  A->>U: logged in
```

## 4. Admin path with AAL2 step-up

Admin pages live at `auth.dunn.dev/admin/*`. AAL is per-flow in
Kratos, so the SSR layer is what enforces it.

```mermaid
sequenceDiagram
  actor U as Admin user
  participant B as Browser
  participant C as Caddy
  participant P as Astro portal (SSR)
  participant K as Kratos

  U->>B: GET /admin/users
  B->>C: cookie ory_session
  C->>K: forward_auth /sessions/whoami
  K->>C: 200 (any AAL)
  C->>P: pass through
  P->>K: getIdentity (admin API)
  P->>P: check metadata_admin.groups has "admin"<br/>check session.aal == aal2
  alt aal1
    P->>B: 302 /self-service/login/browser?aal=aal2&refresh=true
    B->>K: re-auth with second factor
    K->>B: cookie now aal2
    B->>P: retry /admin/users
  else aal2
    P->>B: render admin UI
  end
```

## 5. Trust boundary

One pod, one trust domain. The pod boundary is the wall; in-pod
defense-in-depth is partial and deliberate.

```mermaid
flowchart TB
  subgraph External[Public internet]
    attacker[Attacker]
  end

  subgraph EdgeBoundary[Edge boundary: TLS terminator]
    caddy2[caddy-estate]
  end

  subgraph PodBoundary[Pod boundary: trust unit]
    direction TB
    k2[Kratos]
    h2[Hydra]
    cs2[Consent service]
    p2[Portal]
    pg2[(Postgres)]
  end

  subgraph OtherPod[Other pod e.g. vaultwarden]
    app2[App]
  end

  attacker -->|HTTPS only| caddy2
  caddy2 -->|HTTP, public ports| k2
  caddy2 -->|HTTP, public ports| h2
  caddy2 -->|HTTP, public ports| cs2
  caddy2 -->|HTTP, public ports| p2
  k2 -.shared secret webhook.-> cs2
  p2 -.bearer token.-> cs2
  p2 -->|admin port, no auth<br/>pod-network only| k2
  p2 -->|admin port, no auth<br/>pod-network only| h2
  cs2 -->|admin port, no auth<br/>pod-network only| h2
  k2 --> pg2
  h2 --> pg2
  app2 -.podman netns isolation.- PodBoundary
```

Key: solid arrows are normal traffic, dotted arrows mark application-
layer auth (HMAC webhook, bearer token), the dotted boundary line
between pods is podman network isolation.

## 6. Identity lifecycle

What happens to a family member from "doesn't exist yet" to "off the
system." Admin actions in italics; user actions in regular text.

```mermaid
stateDiagram-v2
  [*] --> Pending: admin creates identity<br/>(traits + metadata_admin.groups)
  Pending --> Enrolling: admin sends enrollment URL<br/>(Signal / iMessage)
  Enrolling --> Active: user registers passkey<br/>(+ optional password fallback)
  Enrolling --> Pending: enrollment URL expires<br/>(admin re-issues)

  Active --> Active: normal use<br/>(90d session, refresh on activity)
  Active --> Recovering: user requests recovery<br/>(non-admin only)
  Recovering --> Active: code verified<br/>+ new credential set
  Recovering --> Active: code expires / aborted

  Active --> Revoked: admin clicks Revoke sessions<br/>(kills Kratos + Hydra remember)
  Revoked --> Active: admin re-enables<br/>(rare, recovery path)
  Revoked --> [*]: admin deletes identity

  note right of Recovering
    Admin group is blocked
    at recovery-gate webhook.
    Admin recovery is console-
    only break-glass.
  end note
```

## 7. Session AAL state machine

A browser session moves between AAL levels. The cookie is the same
across transitions; only the `authenticator_assurance_level` claim
changes. AAL2 step-up is forced at the SSR layer for `/admin/*`.

```mermaid
stateDiagram-v2
  [*] --> Anonymous: no cookie<br/>or expired

  Anonymous --> AAL1: passkey login<br/>(WebAuthn, single factor)
  Anonymous --> AAL1: password login<br/>(fallback)
  Anonymous --> AAL2: passkey + verified email<br/>(if passkey is platform authenticator)

  AAL1 --> AAL2: refresh=true&aal=aal2<br/>(forced by /admin/* SSR gate)
  AAL2 --> AAL1: AAL2 method removed<br/>(rare, admin action)

  AAL1 --> Expired: 90d normal / 1d admin
  AAL2 --> Expired: 90d normal / 1d admin
  Expired --> Anonymous: cookie cleared

  AAL1 --> Revoked: admin Revoke sessions
  AAL2 --> Revoked: admin Revoke sessions
  Revoked --> Anonymous: cookie cleared
```

## 8. Recovery-gate decision

A recovery flow does NOT issue a privileged settings session until the
consent service's `can_interrupt` webhook returns 2xx. Fail-closed: if
the consent service is down, the flow aborts.

```mermaid
stateDiagram-v2
  [*] --> CodeRequested: user submits email
  CodeRequested --> CodeSent: courier sends code<br/>(Fastmail SMTP)
  CodeSent --> CodeVerified: user enters valid code
  CodeSent --> Aborted: code expires (1h)<br/>or wrong code 5x

  CodeVerified --> GateCheck: Kratos calls<br/>consent /can-interrupt
  GateCheck --> Blocked: identity in admin group
  GateCheck --> Allowed: non-admin
  GateCheck --> Aborted: webhook timeout<br/>or non-2xx (fail-closed)

  Blocked --> Aborted: 403 to user<br/>("contact admin")
  Allowed --> SettingsSession: privileged 1h session<br/>(can change credentials)
  SettingsSession --> [*]: user sets new passkey/password
  Aborted --> [*]
```

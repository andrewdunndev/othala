---
name: Books (Library)
description: Ebook + comic library with cross-device reading progress.
url: https://library.dunn.dev
icon: LB
access_group: access-library
auth_kind: oidc
order: 80
disabled: true
---

<!-- TODO: Andrew authors education content. Suggested topics:
- Web reader: SSO sign-in + reading
- Mobile: BookLore companion apps
- Side-loading personal ebooks
- Note: BookLore role-from-OIDC is admin-locked upstream;
  every SSO user is a regular reader. Admin via local admin token.

`disabled: true` until BookLore deployment is validated on carmine
(SERVICES["_library_DISABLED"] in iac).
-->

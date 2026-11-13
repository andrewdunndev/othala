# Contributing

Corrections are welcome on either forge:

- GitLab (canonical): https://gitlab.com/dunn.dev/othala
- GitHub (mirror): https://github.com/andrewdunndev/othala

GitHub pull requests land through GitLab; the mirror then marks them merged.

Corrections are welcome: a false statement, a dead link, a config that does not do what it claims. Feature requests and changes that add configuration surface for a different deployment are not taken; fork it.

## Working on it

[`mise`](https://mise.jdx.dev) provides Node and `just` from `mise.toml`. Then:

```sh
mise install
just setup   # once
just test    # before every push; `just check` is what CI runs
```

`just` lists the other recipes. [`AGENTS.md`](AGENTS.md) is the working contract.

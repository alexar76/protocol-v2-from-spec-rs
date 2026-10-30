# Federating directory node, written from the specification

<!-- aicom-mirror-notice -->
> 🔄 Synced from the [AI-Factory monorepo](https://github.com/alexar76/aicom) (append-only history). **Pull requests are welcome** — merged PRs are imported back and re-synced here. [Issues](https://github.com/alexar76/protocol-v2-from-spec-rs/issues) · [Pull requests](https://github.com/alexar76/protocol-v2-from-spec-rs/pulls)

Not the Python reference hub and not a fork of it. See [OPERATOR.md](OPERATOR.md).

# Protocol v2 manifest and announce, written from the specification

Rust checks for the slices after the receipt verifier:

- capability manifest (§7.3.2) against `test-vectors/`
- federation announce (§7.3.5)
- a read-only live fetch of `/.well-known/ai-market.json` and the manifest it points at

The reference hub sources were not opened. This tree does not count as an independent implementation: the author is the protocol editor. It is not published to GitHub.

`POST /ai-market/v2/channel/open` is implemented only as a body builder. §6.1 says that call transfers tokens into escrow, so the tests do not send it.

```bash
cargo test
```

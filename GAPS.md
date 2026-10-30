# What this pass found

Manifest and announce vectors pass. The live hub at `modelmarket.dev` serves a `.well-known` document with the four required fields, and the manifest it points at verifies under `signer_public_key` with the §7.3.2 canonical.

`POST /ai-market/v2/channel/close` is the depositor's HTTP request. The hub then submits `settleChannel`: pay `usedAmount` to the bound hub, refund the remainder. That is now §6.1 and §8, matching the README and `ecosystem.md`. It is not a second settlement rule, and it is not `refundChannel` (full refund before any debit).

Neither open nor close is sent by these tests. Open transfers tokens into escrow.

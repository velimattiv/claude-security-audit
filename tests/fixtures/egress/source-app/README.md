# Synthetic confused-deputy app (egress test fixture)

A vulnerable-by-design micro-app encoding the deck-2FA bug across **diverse egress
modalities**, used two ways:

1. **CI-runnable (deterministic):** `tests/test-egress.sh` runs the
   `validate-egress.py` candidate extractor over this tree and asserts it
   surfaces the sinks of every modality present (file, proxy, graphql_field,
   sse, presigned_url, db_entity) + the credential mint/consume sites. This
   tests the **coverage gate's recall** — the part the adversarial review flagged
   as un-tested ("the fixture stubs the only hard step: source → inventory").
   If the extractor can't *see* a sink, the fail-closed gate can't demand it.

2. **Local-only (needs Claude):** the same tree is the source for an
   agent-builds-the-inventory-from-source E2E (run via the host's `claude`),
   proving the full Phase-2 → §6.19 loop catches the bug end-to-end. Mutate it
   per the metamorphic battery in `../metamorphic/` to test variants.

The bug in one line: `__sv_` 2FA cookie is minted by `s/[shortId]/verify` and
read only by the resolver `s/[shortId]`; the byte-serving sinks (build-output,
asset-proxy, the GraphQL `content` field, the export presigned-URL) never read
it and serve whenever a publish link exists. Nothing here is real; do not deploy.

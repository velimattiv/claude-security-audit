// FIXTURE (vulnerable by design). Byte-serving content sink for a deck.
// Conditional bypass branch: serves whenever ANY active publishLink exists,
// without ever reading the __sv_ 2FA verification cookie. Confused deputy.
import { createReadStream } from "node:fs";

export default defineEventHandler(async (event) => {
  const deckId = event.context.params.id;
  const session = await getSession(event);

  // authed branch — only a role check, NOT the 2FA verification gate
  if (session && (await canAccessDeck(session.user, deckId))) {
    return createReadStream(buildOutputPath(deckId)).pipe(event.node.res);
  }

  // BYPASS branch — "an active publish link exists" => serve, no cookie check
  if (await hasActivePublishLink(deckId)) {
    return createReadStream(buildOutputPath(deckId)).pipe(event.node.res);
  }

  throw createError({ statusCode: 401 });
});

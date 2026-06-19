// FIXTURE. The ONLY reader of __sv_ — the discovery-layer resolver. It enforces
// 2FA correctly here, then hands out the deckId. The content sinks never repeat
// this check: the gate lives here and nowhere on the byte path. Cross-layer gap.
import { getCookie } from "h3";

export default defineEventHandler(async (event) => {
  const shortId = event.context.params.shortId;
  const link = await getPublishLink(shortId);

  if (link.requireVerification) {
    const cookie = getCookie(event, `__sv_${shortId}`);
    if (!verifyCookieSignature(cookie, shortId) || !(await hasValidVerification(link.id))) {
      throw createError({ statusCode: 401 });
    }
  }
  // deckId handed to the client — it is NOT secret after this point
  return { deckId: link.deckId };
});

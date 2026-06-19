// FIXTURE (vulnerable by design). The ONLY writer of the __sv_ 2FA cookie.
// Mints a verification capability after email-code 2FA — but path-scoped to /s.
import { setCookie } from "h3";

export default defineEventHandler(async (event) => {
  const shortId = event.context.params.shortId;
  const code = getQuery(event).code;
  if (await verifyEmailCode(shortId, code)) {
    // capability cookie — gates the deck, but only the resolver reads it
    setCookie(event, `__sv_${shortId}`, signVerification(shortId), {
      path: `/s/${shortId}`,
      httpOnly: true,
      secure: true,
      sameSite: "lax",
    });
  }
  return { ok: true };
});

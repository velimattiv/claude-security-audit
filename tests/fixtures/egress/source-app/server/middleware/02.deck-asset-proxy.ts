// FIXTURE (vulnerable by design). The third byte-serving sink: an asset proxy
// that streams deck assets whenever a publish link exists. Never reads __sv_.
import { createProxyMiddleware } from "http-proxy-middleware";

export default createProxyMiddleware({
  pathFilter: "/api/decks/:id/assets/**",
  target: "http://internal-asset-store",
  router: async (req) => {
    const deckId = extractDeckId(req.url);
    if (await hasActivePublishLink(deckId)) {
      return "http://internal-asset-store"; // serves bytes, unauthenticated
    }
    return undefined;
  },
});

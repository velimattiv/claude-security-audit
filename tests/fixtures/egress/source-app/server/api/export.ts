// FIXTURE (vulnerable by design). Two more egress modalities:
//  (1) a presigned URL that hands out durable unauthenticated access to a deck;
//  (2) an SSE stream that pushes deck content.
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";

export async function exportDeck(event) {
  const deckId = getQuery(event).deckId;
  // presigned URL — capability that lives OUTSIDE any future request gate
  const url = await getSignedUrl(s3, deckGetObject(deckId), { expiresIn: 86400 });

  // SSE stream of deck content, no gate
  event.node.res.setHeader("Content-Type", "text/event-stream");
  for await (const chunk of streamDeck(deckId)) {
    event.node.res.write(`data: ${chunk}\n\n`);
  }
  return url;
}

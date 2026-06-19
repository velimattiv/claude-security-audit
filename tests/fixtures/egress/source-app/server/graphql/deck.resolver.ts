// FIXTURE (vulnerable by design). Sub-route egress: a GraphQL field resolver
// returns the deck's rendered content with no gate. One endpoint (the GraphQL
// POST), many field-level egress points — route-granular review misses this.
import { Resolver, ResolveField, Parent } from "@nestjs/graphql";

@Resolver("Deck")
export class DeckResolver {
  @ResolveField("content")
  resolve(@Parent() deck) {
    // returns sensitive bytes; no verification / ownership check
    return loadDeckContent(deck.id);
  }
}

// FIXTURE — correctly scoped collection. MUST produce zero findings.
// This is the precision half of the test: a lens that flags this is unusable.
import { and, eq, isNull } from 'drizzle-orm'
import { decks } from '../../db/schema'
import { requireAuth } from '../../utils/auth'
import { db } from '../../db'

export default defineEventHandler(async (event) => {
  const session = await requireAuth(event)
  const mine = await db
    .select()
    .from(decks)
    .where(and(eq(decks.ownerId, session.user.id), isNull(decks.deletedAt)))
  return { data: mine }
})

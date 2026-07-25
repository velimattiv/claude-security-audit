// FIXTURE — second unscoped collection. Same class, different endpoint: this is
// what "fix the pattern in one place" leaves behind.
import { isNull } from 'drizzle-orm'
import { decks } from '../../db/schema'
import { requireAuth } from '../../utils/auth'
import { db } from '../../db'

export default defineEventHandler(async (event) => {
  await requireAuth(event)
  const all = await db.select().from(decks).where(isNull(decks.deletedAt))
  return { data: all }
})

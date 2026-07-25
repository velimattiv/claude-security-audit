// FIXTURE — the inventory will CLAIM this is caller_bound. It is not: the
// predicate constrains WHICH rows (status, soft-delete), never WHOSE. C5 must
// refuse the claim and rewrite the row to unscoped, so a wrong inventory cannot
// launder a real gap into a pass.
import { and, eq, isNull } from 'drizzle-orm'
import { reports } from '../../db/schema'
import { requireAuth } from '../../utils/auth'
import { db } from '../../db'

export default defineEventHandler(async (event) => {
  await requireAuth(event)
  const rows = await db
    .select()
    .from(reports)
    .where(and(eq(reports.status, 'published'), isNull(reports.deletedAt)))
  return { data: rows }
})

// Correctly scoped by Postgres row-level security. The caller's identity is
// pushed into a session GUC by the connection middleware, and the predicate
// reads it back with current_setting(). The GUC NAME is a single-quoted string
// literal, which is what made v2.5 score this handler as having no caller
// predicate at all: C5 fired, rewrote the row to unscoped, and C1 followed.
export default defineEventHandler(async (event) => {
  const session = await requireAuth(event)
  const rows = await db.execute(sql`SELECT id, name FROM org WHERE owner_id = NULLIF(current_setting('app.user_teammate_id', true), '')::uuid`)
  return { data: rows }
})

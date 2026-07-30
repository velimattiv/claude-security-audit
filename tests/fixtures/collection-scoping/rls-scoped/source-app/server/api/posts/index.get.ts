// The control. Same tagged-template shape as its two siblings, but the WHERE
// binds a LITERAL — it constrains which rows, not whose. Teaching the scanner
// to read tagged template bodies must not also teach it to read the string
// literals inside them as caller references: this handler must still be caught.
export default defineEventHandler(async (event) => {
  const session = await requireAuth(event)
  const rows = await db.execute(sql`SELECT * FROM post WHERE status = 'published'`)
  return { data: rows }
})

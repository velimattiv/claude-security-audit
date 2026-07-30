// Correctly scoped by interpolation into a tagged template. Until v2.6 the
// backtick sat in the same delimiter set as ' and ", so the whole body — the
// ${...} included — was blanked before scoring, and this read as a query with
// no predicate whatsoever.
export default defineEventHandler(async (event) => {
  const session = await requireAuth(event)
  const rows = await tx.execute(sql`SELECT * FROM task WHERE teammate_id = ${session.teammateId}`)
  return { data: rows }
})

// FIXTURE — faithful reproduction of the handler shape that passed a full v2.4
// audit with a clean bill while disclosing every user's private resources to any
// authenticated caller. Do not "fix" this file; it is the acceptance test.
//
// Three properties make it hard:
//   1. the gate EXISTS and looks correct   (requireRole)
//   2. the WHERE clause is NOT empty       (but constrains which, not whose)
//   3. a permission is computed per row and ATTACHED, never applied
import { and, eq, isNull } from 'drizzle-orm'
import { decks, deckMembers } from '../../db/schema'
import { requireRole } from '../../utils/auth'
import { db } from '../../db'

function applyCanWrite(nodes: TreeNode[], session: Session): TreeNode[] {
  // Computes a per-row permission and DECORATES with it. Never filters.
  return nodes.map((n) => ({
    ...n,
    canWrite: n.ownerId === session.user.id,
    children: n.children ? applyCanWrite(n.children, session) : undefined,
  }))
}

export default defineEventHandler(async (event) => {
  const session = await requireRole(event, 'reader')

  const rows = await db
    .select({
      id: decks.id,
      title: decks.title,
      description: decks.description,
      slideCount: decks.slideCount,
      filePath: decks.filePath,
      ownerId: decks.ownerId,
    })
    .from(decks)
    .where(and(eq(decks.scope, 'user'), isNull(decks.deletedAt)))

  const rawTree = buildTree(rows)
  const tree = applyCanWrite(rawTree, session)

  return { data: tree }
})

// FIXTURE — a genuinely public catalogue. Product is on profile.public_resources,
// so this MUST produce zero findings even though it is unscoped by construction.
import { eq } from 'drizzle-orm'
import { products } from '../../db/schema'
import { db } from '../../db'

export default defineEventHandler(async () => {
  const rows = await db.select().from(products).where(eq(products.published, true))
  return { data: rows }
})

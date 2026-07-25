// FIXTURE — the test that PINS the bug. It asserts another principal's folder is
// PRESENT (with canWrite:false) rather than absent. C4 must flag this: the
// insecure behaviour is written down as the expected behaviour, so a correct fix
// will look like a broken test.
import { describe, expect, it } from 'vitest'

describe('GET /api/content/tree', () => {
  it('returns the full tree for a reader', async () => {
    const res = await $fetch('/api/content/tree', { headers: readerHeaders })
    expect(res.data).toHaveLength(3)
  })

  it('marks other users folders read-only', async () => {
    const res = await $fetch('/api/content/tree', { headers: readerHeaders })
    const otherUserFolder = res.data.find((n) => n.name === 'other-user')
    expect(otherUserFolder).toBeDefined()
    expect(otherUserFolder.canWrite).toBe(false)
  })
})

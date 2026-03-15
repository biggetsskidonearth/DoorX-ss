// pages/api/keys/revoke.ts — Admin endpoint to revoke a key
// POST /api/keys/revoke  Body: { key, reason }  Header: x-doorx-internal

import type { NextApiRequest, NextApiResponse } from 'next'
import { prisma } from '../../../lib/prisma'
import { hashIP } from '../../../lib/security'

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' })
  if (req.headers['x-doorx-internal'] !== process.env.INTERNAL_API_SECRET) {
    return res.status(401).json({ error: 'Unauthorized' })
  }

  const { key, reason } = req.body || {}
  if (!key) return res.status(400).json({ error: 'key required' })

  try {
    const record = await prisma.key.findUnique({ where: { key } })
    if (!record) return res.status(404).json({ error: 'KEY_NOT_FOUND' })

    await prisma.key.update({
      where: { key },
      data: { isRevoked: true, isActive: false, revokeReason: reason || 'Admin revoke' },
    })
    await prisma.auditLog.create({ data: { keyId: record.id, action: 'KEY_REVOKED', detail: JSON.stringify({ reason }) } })
    return res.status(200).json({ success: true })
  } catch (err: any) {
    return res.status(500).json({ error: err.message })
  }
}

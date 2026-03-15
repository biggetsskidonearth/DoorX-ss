// pages/api/keys/lookup.ts — Admin: look up keys for a Roblox user
// GET /api/keys/lookup?robloxUserId=XXX  Header: x-doorx-internal

import type { NextApiRequest, NextApiResponse } from 'next'
import { prisma } from '../../../lib/prisma'

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== 'GET') return res.status(405).json({ error: 'Method not allowed' })
  if (req.headers['x-doorx-internal'] !== process.env.INTERNAL_API_SECRET) {
    return res.status(401).json({ error: 'Unauthorized' })
  }

  const { robloxUserId } = req.query
  if (!robloxUserId) return res.status(400).json({ error: 'robloxUserId required' })

  try {
    const keys = await prisma.key.findMany({
      where: { robloxUserId: BigInt(robloxUserId as string) },
      select: { key: true, plan: true, isActive: true, isRevoked: true, expiresAt: true, createdAt: true, lastUsedAt: true, useCount: true },
      orderBy: { createdAt: 'desc' },
    })
    return res.status(200).json({ keys: keys.map(k => ({ ...k, robloxUserId: undefined })) })
  } catch (err: any) {
    return res.status(500).json({ error: err.message })
  }
}

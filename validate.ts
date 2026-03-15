// pages/api/keys/validate.ts
// POST /api/keys/validate
// Body: { key, sig }      — called by the DoorX program to verify a key
// Returns: { valid, plan } or { valid: false, error }

import type { NextApiRequest, NextApiResponse } from 'next'
import { prisma } from '../../../lib/prisma'
import { hashIP, checkRateLimit, isLockedDown, triggerLockdown } from '../../../lib/security'

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' })

  const ip = (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() || req.socket.remoteAddress || '0.0.0.0'
  const ipHash = hashIP(ip)
  const origin = req.headers.origin || ''

  // CORS — only allow from DoorX domains + program
  res.setHeader('Access-Control-Allow-Origin', origin || '*')
  res.setHeader('Access-Control-Allow-Methods', 'POST')
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type')

  // Lockdown check
  if (await isLockedDown(ipHash)) {
    return res.status(423).json({ valid: false, error: 'IP_LOCKED_DOWN' })
  }

  // Rate limit: 20 validates per minute per IP (program calls this)
  const rl = await checkRateLimit(ipHash, 'validate', { windowMs: 60_000, max: 20 })
  if (!rl.allowed) {
    // Too many validate calls = suspicious
    const floodCount = await checkRateLimit(ipHash, 'validate_flood', { windowMs: 300_000, max: 3 })
    if (!floodCount.allowed) {
      await triggerLockdown(ipHash, 'VALIDATE_FLOOD', 3_600_000)
      await prisma.auditLog.create({ data: { action: 'LOCKDOWN_TRIGGERED', ipHash, detail: JSON.stringify({ reason: 'VALIDATE_FLOOD' }) } })
    }
    return res.status(429).json({ valid: false, error: 'RATE_LIMITED' })
  }

  const { key, sig } = req.body || {}

  if (!key || typeof key !== 'string' || key.length > 60) {
    return res.status(400).json({ valid: false, error: 'INVALID_KEY_FORMAT' })
  }

  // Key format check: DoorX-{Plan}-XXXXXXXXXXX
  if (!/^DoorX-(Free|Normal|Premium)-[A-Z2-9]{11}$/.test(key)) {
    await prisma.auditLog.create({
      data: { action: 'UNAUTHORIZED_FETCH', ipHash, detail: JSON.stringify({ reason: 'MALFORMED_KEY', key: key.slice(0, 20) }) }
    })
    return res.status(400).json({ valid: false, error: 'MALFORMED_KEY' })
  }

  try {
    const record = await prisma.key.findUnique({ where: { key } })

    if (!record) {
      await prisma.auditLog.create({ data: { action: 'KEY_VALIDATED', ipHash, detail: JSON.stringify({ result: 'NOT_FOUND' }) } })
      return res.status(200).json({ valid: false, error: 'KEY_NOT_FOUND' })
    }

    if (record.isRevoked) {
      await prisma.auditLog.create({ data: { keyId: record.id, action: 'KEY_VALIDATED', ipHash, detail: JSON.stringify({ result: 'REVOKED', reason: record.revokeReason }) } })
      return res.status(200).json({ valid: false, error: 'KEY_REVOKED', reason: record.revokeReason })
    }

    if (!record.isActive) {
      return res.status(200).json({ valid: false, error: 'KEY_INACTIVE' })
    }

    // Check expiry (Free trial)
    if (record.expiresAt && record.expiresAt < new Date()) {
      await prisma.key.update({ where: { id: record.id }, data: { isActive: false } })
      await prisma.auditLog.create({ data: { keyId: record.id, action: 'KEY_EXPIRED', ipHash } })
      return res.status(200).json({ valid: false, error: 'KEY_EXPIRED' })
    }

    // Update last used
    await prisma.key.update({
      where: { id: record.id },
      data: { lastUsedAt: new Date(), useCount: { increment: 1 } }
    })

    await prisma.auditLog.create({
      data: { keyId: record.id, action: 'KEY_VALIDATED', ipHash, userAgent: req.headers['user-agent'], detail: JSON.stringify({ result: 'VALID' }) }
    })

    return res.status(200).json({
      valid: true,
      plan: record.plan,
      robloxUserId: record.robloxUserId.toString(),
      robloxName: record.robloxName,
      expiresAt: record.expiresAt,
    })
  } catch (err: any) {
    console.error('[validate]', err)
    return res.status(500).json({ valid: false, error: 'INTERNAL_ERROR' })
  }
}

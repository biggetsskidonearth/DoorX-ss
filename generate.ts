// pages/api/keys/generate.ts
// POST /api/keys/generate
// Body: { plan, robloxUserId, robloxName, sessionSig }
// Headers: x-doorx-internal (required)
// Returns: { key } or { error }

import type { NextApiRequest, NextApiResponse } from 'next'
import { prisma } from '../../../lib/prisma'
import {
  generateKeyString,
  hashIP,
  checkRateLimit,
  isLockedDown,
  triggerLockdown,
  validateOrigin,
} from '../../../lib/security'
import { Plan } from '@prisma/client'

const PLAN_MAP: Record<string, Plan> = {
  free: Plan.Free,
  normal: Plan.Normal,
  premium: Plan.Premium,
}

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  // ── Method guard
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' })

  // ── CORS
  const origin = req.headers.origin || ''
  const allowed = (process.env.ALLOWED_ORIGINS || '').split(',').map(s => s.trim())
  if (allowed.length && !allowed.includes(origin)) {
    return res.status(403).json({ error: 'Origin not allowed' })
  }
  res.setHeader('Access-Control-Allow-Origin', origin || '*')
  res.setHeader('Access-Control-Allow-Methods', 'POST')
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, x-doorx-internal')

  // ── Auth: require internal secret
  if (req.headers['x-doorx-internal'] !== process.env.INTERNAL_API_SECRET) {
    return res.status(401).json({ error: 'Unauthorized' })
  }

  const ip = (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() || req.socket.remoteAddress || '0.0.0.0'
  const ipHash = hashIP(ip)

  // ── Lockdown check
  if (await isLockedDown(ipHash)) {
    return res.status(423).json({ error: 'IP_LOCKED_DOWN', message: 'Access temporarily suspended.' })
  }

  // ── Rate limit: 5 key generations per hour per IP
  const rl = await checkRateLimit(ipHash, 'generate', { windowMs: 3_600_000, max: 5 })
  if (!rl.allowed) {
    await prisma.auditLog.create({
      data: { action: 'RATE_LIMITED', ipHash, detail: JSON.stringify({ action: 'generate' }) }
    })
    return res.status(429).json({ error: 'RATE_LIMITED', resetAt: rl.resetAt, remaining: 0 })
  }

  // ── Input validation
  const { plan, robloxUserId, robloxName, sessionSig } = req.body || {}

  if (!plan || !PLAN_MAP[plan.toLowerCase()]) {
    return res.status(400).json({ error: 'INVALID_PLAN', message: 'plan must be free, normal, or premium' })
  }
  if (!robloxUserId || isNaN(Number(robloxUserId))) {
    return res.status(400).json({ error: 'INVALID_USER_ID' })
  }
  if (!robloxName || typeof robloxName !== 'string' || robloxName.length > 20) {
    return res.status(400).json({ error: 'INVALID_USERNAME' })
  }
  if (!sessionSig || typeof sessionSig !== 'string') {
    return res.status(400).json({ error: 'MISSING_SESSION_SIG' })
  }

  const prismaplan = PLAN_MAP[plan.toLowerCase()]
  const userId = BigInt(robloxUserId)
  const expiresAt = prismaplan === Plan.Free ? new Date(Date.now() + 3_600_000) : null // 1h for free

  try {
    // ── Check if key already exists for this user+plan
    const existing = await prisma.key.findUnique({
      where: { robloxUserId_plan: { robloxUserId: userId, plan: prismaplan } }
    })

    if (existing && !existing.isRevoked) {
      // Return existing key (idempotent)
      await prisma.auditLog.create({
        data: { keyId: existing.id, action: 'KEY_VALIDATED', ipHash, detail: JSON.stringify({ reason: 'existing_returned' }) }
      })
      return res.status(200).json({ key: existing.key, existing: true })
    }

    // ── Generate new key (unique constraint retry loop)
    let keyString = ''
    let attempts = 0
    while (attempts < 10) {
      const candidate = generateKeyString(prismaplan)
      const conflict = await prisma.key.findUnique({ where: { key: candidate } })
      if (!conflict) { keyString = candidate; break; }
      attempts++
    }
    if (!keyString) throw new Error('KEY_GENERATION_EXHAUSTED')

    // ── Save to DB
    const record = await prisma.key.upsert({
      where: { robloxUserId_plan: { robloxUserId: userId, plan: prismaplan } },
      update: { key: keyString, robloxName, ipHash, sessionSig, isActive: true, isRevoked: false, expiresAt, updatedAt: new Date() },
      create: { key: keyString, plan: prismaplan, robloxUserId: userId, robloxName, ipHash, sessionSig, expiresAt },
    })

    // ── Audit
    await prisma.auditLog.create({
      data: { keyId: record.id, action: 'KEY_GENERATED', ipHash, userAgent: req.headers['user-agent'], origin, detail: JSON.stringify({ plan: prismaplan, robloxUserId: String(userId) }) }
    })

    return res.status(201).json({ key: record.key, expiresAt: record.expiresAt })
  } catch (err: any) {
    console.error('[generate]', err)
    return res.status(500).json({ error: 'INTERNAL_ERROR', message: err.message })
  }
}

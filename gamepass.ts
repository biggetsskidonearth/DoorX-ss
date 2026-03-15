// pages/api/verify/gamepass.ts
// POST /api/verify/gamepass
// Body: { username, plan }
// Returns: { verified, userId, username, displayName } or { error }
// This route is the SERVER-SIDE proxy to Roblox — no CORS issues, no proxy needed.

import type { NextApiRequest, NextApiResponse } from 'next'
import { hashIP, checkRateLimit, isLockedDown } from '../../../lib/security'

const GP_IDS: Record<string, number> = {
  normal:  1748364695,
  premium: 1748262922,
}

// Server-side fetch with retry
async function sfetch(url: string, opts: RequestInit = {}, retries = 3): Promise<Response> {
  let lastErr: Error = new Error('unknown')
  for (let i = 0; i < retries; i++) {
    try {
      const ctrl = new AbortController()
      const tid = setTimeout(() => ctrl.abort(), 10_000)
      const r = await fetch(url, { ...opts, signal: ctrl.signal })
      clearTimeout(tid)
      if (r.status === 429) { await new Promise(r => setTimeout(r, 1500 * (i + 1))); continue; }
      return r
    } catch (e: any) { lastErr = e; await new Promise(r => setTimeout(r, 800 * (i + 1))); }
  }
  throw lastErr
}

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' })

  const ip = (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() || req.socket.remoteAddress || '0.0.0.0'
  const ipHash = hashIP(ip)

  // CORS
  res.setHeader('Access-Control-Allow-Origin', req.headers.origin || '*')
  res.setHeader('Access-Control-Allow-Methods', 'POST')
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type')

  if (await isLockedDown(ipHash)) {
    return res.status(423).json({ error: 'IP_LOCKED_DOWN' })
  }

  // Rate limit: 10 verification attempts per 5 minutes per IP
  const rl = await checkRateLimit(ipHash, 'verify_gamepass', { windowMs: 300_000, max: 10 })
  if (!rl.allowed) {
    return res.status(429).json({ error: 'RATE_LIMITED', resetAt: rl.resetAt })
  }

  const { username, plan } = req.body || {}

  // Input validation
  if (!username || typeof username !== 'string' || !/^[a-zA-Z0-9_]{3,20}$/.test(username.trim())) {
    return res.status(400).json({ error: 'INVALID_USERNAME' })
  }
  if (!plan || !GP_IDS[plan.toLowerCase()]) {
    return res.status(400).json({ error: 'INVALID_PLAN' })
  }

  const cleanName = username.trim()
  const gpId = GP_IDS[plan.toLowerCase()]

  try {
    // ── Step 1: Resolve username → userId (server-side, no CORS)
    const userRes = await sfetch('https://users.roblox.com/v1/usernames/users', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ usernames: [cleanName], excludeBannedUsers: false }),
    })

    if (!userRes.ok) {
      return res.status(502).json({ error: 'ROBLOX_USER_API_ERROR', status: userRes.status })
    }

    const userData = await userRes.json()
    if (!userData?.data?.length) {
      return res.status(404).json({ error: 'USER_NOT_FOUND' })
    }

    const user = userData.data[0]
    const userId: number = user.id

    // ── Step 2: Check gamepass ownership (server-side)
    const invRes = await sfetch(
      `https://inventory.roblox.com/v1/users/${userId}/items/GamePass/${gpId}`
    )

    if (!invRes.ok) {
      // 403 = private inventory but gamepasses still queryable — retry
      if (invRes.status === 403) {
        // Try the new endpoint
        const gpRes = await sfetch(
          `https://apis.roblox.com/game-passes/v1/users/${userId}/game-passes`
        ).catch(() => null)

        if (gpRes?.ok) {
          const gpData = await gpRes.json()
          const items = gpData?.gamePassProductItems || gpData?.data || []
          const owned = items.some((gp: any) => Number(gp.gamePassId) === gpId || Number(gp.id) === gpId)
          return res.status(200).json({ verified: owned, userId: String(userId), username: user.name, displayName: user.displayName || user.name })
        }
      }
      return res.status(502).json({ error: 'ROBLOX_INVENTORY_API_ERROR', status: invRes.status })
    }

    const invData = await invRes.json()
    const owned = Array.isArray(invData?.data) && invData.data.length > 0

    return res.status(200).json({
      verified: owned,
      userId: String(userId),
      username: user.name,
      displayName: user.displayName || user.name,
    })
  } catch (err: any) {
    console.error('[verify/gamepass]', err)
    return res.status(500).json({ error: 'INTERNAL_ERROR', message: err.message })
  }
}

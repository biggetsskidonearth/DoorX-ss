// middleware/rateLimit.ts — Edge middleware (runs before every API route on Vercel Edge)
import { NextResponse } from 'next/server'
import type { NextRequest } from 'next/server'

const BLOCKED_PATHS = ['/api/admin'] // paths fully blocked in prod

export function middleware(req: NextRequest) {
  const { pathname } = req.nextUrl

  // Block obviously forbidden paths
  if (BLOCKED_PATHS.some(p => pathname.startsWith(p))) {
    return new NextResponse(JSON.stringify({ error: 'Forbidden' }), { status: 403 })
  }

  // Security headers on all API responses
  const res = NextResponse.next()
  res.headers.set('X-Content-Type-Options', 'nosniff')
  res.headers.set('X-Frame-Options', 'DENY')
  res.headers.set('X-XSS-Protection', '1; mode=block')
  res.headers.set('Referrer-Policy', 'strict-origin-when-cross-origin')
  res.headers.set('Permissions-Policy', 'camera=(), microphone=(), geolocation=()')

  // Remove server identification
  res.headers.delete('x-powered-by')

  return res
}

export const config = { matcher: '/api/:path*' }

import { clearCookie } from '../../_lib/session.mjs'
export async function onRequestPost() {
  return new Response(JSON.stringify({ ok: true }), {
    status: 200, headers: { 'content-type': 'application/json', 'set-cookie': clearCookie() },
  })
}

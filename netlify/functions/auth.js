const crypto = require("crypto")

exports.handler = async (event) => {
  const clientId = process.env.GITHUB_CLIENT_ID
  const clientSecret = process.env.GITHUB_CLIENT_SECRET
  if (!clientId || !clientSecret) {
    return { statusCode: 500, body: "Missing GITHUB_CLIENT_ID or GITHUB_CLIENT_SECRET environment variable" }
  }

  const state = signState(clientSecret)
  const params = new URLSearchParams({
    client_id: clientId,
    redirect_uri: `${baseUrl(event)}/callback`,
    scope: "repo,user",
    state,
  })

  return {
    statusCode: 302,
    headers: {
      Location: `https://github.com/login/oauth/authorize?${params.toString()}`,
    },
    body: "",
  }
}

function baseUrl(event) {
  const host = event.headers["x-forwarded-host"] || event.headers.host
  const proto = event.headers["x-forwarded-proto"] || "https"
  return `${proto}://${host}`
}

// Self-verifying state instead of a cookie: the OAuth redirect bounces through
// github.com and back, and cookies set right before that kind of cross-site
// bounce get dropped or capped by several browsers' anti-tracking heuristics.
// Signing nonce+timestamp with the client secret lets /callback verify the
// state on its own, with no server-side or cookie storage to round-trip.
function signState(secret) {
  const nonce = crypto.randomBytes(16).toString("hex")
  const timestamp = Date.now().toString()
  const payload = `${nonce}.${timestamp}`
  const signature = crypto.createHmac("sha256", secret).update(payload).digest("hex")
  return `${payload}.${signature}`
}

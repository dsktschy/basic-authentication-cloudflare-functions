// https://developers.cloudflare.com/pages/platform/functions/middleware/#chain-middleware
const handleError: PagesFunction = async ({ next }) => {
  try {
    return await next()
  } catch (err) {
    return new Response(`${err.message}\n${err.stack}`, { status: 500 })
  }
}

// https://developers.cloudflare.com/workers/examples/basic-auth/
// https://developers.cloudflare.com/pages/how-to/refactor-a-worker-to-pages-functions/
const handleRequest: PagesFunction<{
  BASIC_USER: string
  BASIC_PASS: string
}> = async ({ next, request, env }) => {
  const { pathname } = new URL(request.url)
  switch (pathname) {
    // Pages that anyone can access.
    case '/':
      return await next()
    // Pages that cannot be accessed by unauthenticated users.
    default:
      // The "Authorization" header is sent when authenticated.
      if (!request.headers.has('Authorization'))
        // Not authenticated.
        return new Response('You need to login.', {
          status: 401,
          headers: {
            // Prompts the user for credentials.
            'WWW-Authenticate': 'Basic realm="my scope", charset="UTF-8"'
          }
        })
      const Authorization = request.headers.get('Authorization')
      const [scheme, encoded] = Authorization.split(' ')
      // The Authorization header must start with Basic, followed by a space.
      if (!encoded || scheme !== 'Basic')
        return new Response('Malformed authorization header.', {
          status: 400
        })
      // Decodes the base64 value and performs unicode normalization.
      // @see https://datatracker.ietf.org/doc/html/rfc7613#section-3.3.2 (and #section-4.2.2)
      // @see https://dev.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/String/normalize
      const buffer = Uint8Array.from(atob(encoded), character =>
        character.charCodeAt(0)
      )
      const decoded = new TextDecoder().decode(buffer).normalize()
      // The username & password are split by the first colon.
      //=> example: "username:password"
      const index = decoded.indexOf(':')
      // The user & password are split by the first colon and MUST NOT contain control characters.
      // @see https://tools.ietf.org/html/rfc5234#appendix-B.1 (=> "CTL = %x00-1F / %x7F")
      if (index === -1 || /[\0-\x1F\x7F]/.test(decoded))
        return new Response('Invalid authorization value.', { status: 400 })
      const user = decoded.substring(0, index)
      const pass = decoded.substring(index + 1)
      if (env.BASIC_USER !== user)
        return new Response('Invalid credentials.', { status: 401 })
      if (env.BASIC_PASS !== pass)
        return new Response('Invalid credentials.', { status: 401 })
      return await next()
  }
}

// https://developers.cloudflare.com/pages/platform/functions/middleware/#chain-middleware
export const onRequest = [handleError, handleRequest]

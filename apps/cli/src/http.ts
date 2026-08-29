/**
 * How the CLI talks to the API.
 *
 * Both push commands need the same two things before they do any work: a
 * token, and a transport that will not leak it. They each had their own copy
 * of the first and neither had the second.
 */
/**
 * The API refuses every route but /health without a token, so a missing one is
 * worth naming here rather than surfacing as an opaque 401 from a fetch.
 */
export function authHeader(token: string | undefined): Record<string, string> {
  const value = token ?? process.env['ASSAY_TOKEN'];
  if (value === undefined || value === '') {
    throw new Error(
      'no API token: pass --token, or set ASSAY_TOKEN.\n' +
        'The server prints one on first start; mint more with POST /tokens.',
    );
  }
  return { authorization: `Bearer ${value}` };
}

/**
 * Refuse to put a bearer token on the wire in the clear.
 *
 * The token is a credential for an inventory of an organization's weakest
 * cryptography. Sending it over plain HTTP to anything but the developer's own
 * machine hands both to anyone on the path - a notably poor look for this
 * particular product. localhost is allowed because that is where the API runs
 * during development, and it never leaves the host.
 */
export function requestHeaders(api: string, token: string | undefined): Record<string, string> {
  assertTransportSafe(api);
  return { 'content-type': 'application/json', ...authHeader(token) };
}

const LOOPBACK = new Set(['localhost', '127.0.0.1', '::1', '[::1]']);

export function assertTransportSafe(api: string): void {
  let url: URL;
  try {
    url = new URL(api);
  } catch {
    throw new Error(`--api is not a URL: ${api}`);
  }
  if (url.protocol === 'https:') return;
  // `new URL('localhost:3001')` parses, with protocol "localhost:" - so a
  // missing scheme reads as a bare host and has to be named as such rather
  // than reported as a cleartext problem.
  if (url.protocol !== 'http:') {
    throw new Error(`--api must be an http(s) URL, not ${url.protocol}//: ${api}`);
  }
  if (LOOPBACK.has(url.hostname)) return;
  if (process.env['ASSAY_ALLOW_CLEARTEXT'] === '1') return;
  throw new Error(
    `refusing to send an API token to ${url.origin} in the clear.\n` +
      'Use https://, or set ASSAY_ALLOW_CLEARTEXT=1 if this is a trusted private network.',
  );
}

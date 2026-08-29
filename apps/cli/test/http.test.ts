import { afterEach, describe, expect, it } from 'vitest';
import { assertTransportSafe, authHeader, requestHeaders } from '../src/http.js';

const saved = { ...process.env };
afterEach(() => {
  process.env = { ...saved };
});

describe('the token never goes on the wire in the clear', () => {
  it('allows https anywhere', () => {
    expect(() => assertTransportSafe('https://assay.example.com')).not.toThrow();
  });

  it('allows http to loopback, which is where the dev API runs', () => {
    for (const api of ['http://localhost:3001', 'http://127.0.0.1:3001', 'http://[::1]:3001']) {
      expect(() => assertTransportSafe(api)).not.toThrow();
    }
  });

  it('refuses http to anything else', () => {
    // A bearer token for an inventory of an estate's weakest cryptography,
    // sent in plaintext, is a notably poor look for this particular product.
    expect(() => assertTransportSafe('http://assay.internal.example.com')).toThrow(/in the clear/);
    expect(() => assertTransportSafe('http://10.0.0.4:3001')).toThrow(/in the clear/);
  });

  it('can be overridden deliberately, not accidentally', () => {
    process.env['ASSAY_ALLOW_CLEARTEXT'] = '1';
    expect(() => assertTransportSafe('http://10.0.0.4:3001')).not.toThrow();
  });

  it('rejects something that is not a URL at all', () => {
    expect(() => assertTransportSafe('localhost:3001')).toThrow(/must be an http\(s\) URL/);
    expect(() => assertTransportSafe('not a url')).toThrow(/not a URL/);
  });
});

describe('the missing token is found before the work, not after', () => {
  it('throws from requestHeaders, which push calls before scanning', () => {
    delete process.env['ASSAY_TOKEN'];
    expect(() => requestHeaders('https://assay.example.com', undefined)).toThrow(/no API token/);
  });

  it('checks the transport before the token, so both problems surface', () => {
    delete process.env['ASSAY_TOKEN'];
    expect(() => requestHeaders('http://10.0.0.4', 'assay_x_y')).toThrow(/in the clear/);
  });

  it('carries the token and the content type when both are fine', () => {
    expect(requestHeaders('https://a.example.com', 'assay_abc_def')).toEqual({
      'content-type': 'application/json',
      authorization: 'Bearer assay_abc_def',
    });
  });

  it('falls back to ASSAY_TOKEN', () => {
    process.env['ASSAY_TOKEN'] = 'assay_env_token';
    expect(authHeader(undefined)).toEqual({ authorization: 'Bearer assay_env_token' });
  });
});

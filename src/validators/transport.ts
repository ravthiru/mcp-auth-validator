import { ValidationResult } from '../types.js';

export async function validateTransportSecurity(
  mcpUrl: string
): Promise<ValidationResult[]> {
  const results: ValidationResult[] = [];
  const target = new URL(mcpUrl);
  const isLocalhost =
    target.hostname === 'localhost' ||
    target.hostname === '127.0.0.1' ||
    target.hostname === '::1';

  // 1. HTTPS Enforcement for Non-Localhost Endpoints
  if (!isLocalhost && target.protocol !== 'https:') {
    results.push({
      id: 'TRANSPORT-HTTPS',
      name: 'HTTPS required for remote MCP endpoints',
      status: 'FAIL',
      details: `Remote endpoint "${mcpUrl}" uses insecure HTTP instead of HTTPS.`,
      specRef: 'MCP Authorization Spec - Transport Security',
    });
  } else {
    results.push({
      id: 'TRANSPORT-HTTPS',
      name: 'Transport protocol security check',
      status: 'PASS',
      details: isLocalhost
        ? 'Localhost HTTP endpoint allowed for local testing.'
        : 'Remote endpoint enforces HTTPS.',
      specRef: 'MCP Authorization Spec - Transport Security',
    });
  }

  // 2. DNS Rebinding Protection (Untrusted Origin Header)
  const evilOriginRes = await fetch(mcpUrl, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Accept: 'application/json, text/event-stream',
      Origin: 'https://example.com',
    },
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      method: 'tools/list',
    }),
  });

  results.push({
    id: 'TRANSPORT-ORIGIN',
    name: 'Reject untrusted Origin header (DNS Rebinding)',
    status: evilOriginRes.status === 403 ? 'PASS' : 'FAIL',
    details:
      evilOriginRes.status === 403
        ? 'Server correctly rejected untrusted Origin header with HTTP 403.'
        : `Expected HTTP 403 Forbidden for untrusted Origin, got HTTP ${evilOriginRes.status}.`,
    specRef: 'MCP Security Best Practices - DNS Rebinding',
  });

  // 3. SDK v2 Stateless HTTP Check (Ensure no legacy SSE GET stream exposure)
  const getRes = await fetch(mcpUrl, {
    method: 'GET',
    headers: {
      Accept: 'text/event-stream',
    },
  });

  const isProperlyLockedDown =
    getRes.status === 401 || getRes.status === 405 || getRes.status === 403;

  results.push({
    id: 'TRANSPORT-GET-GUARD',
    name: 'Unauthenticated HTTP GET protection',
    status: isProperlyLockedDown ? 'PASS' : 'WARN',
    details: isProperlyLockedDown
      ? `Unauthenticated GET request properly rejected (HTTP ${getRes.status}).`
      : `Unauthenticated GET returned HTTP ${getRes.status}; ensure GET streams require auth or return 405 in stateless v2 mode.`,
    specRef: 'MCP Spec 2026-07-28 - Streamable HTTP',
  });

  return results;
}

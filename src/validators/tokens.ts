import { Client } from '@modelcontextprotocol/client';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/client/streamableHttp';
import { SignJWT, generateKeyPair } from 'jose';
import { ValidationResult } from '../types.js';

export interface MockIdpHandle {
  issuer: string;
  mintToken: (options: {
    audience: string;
    scope?: string;
    expiresIn?: string;
  }) => Promise<string>;
}

export async function validateTokenSecurity(
  mcpUrl: string,
  mockIdp: MockIdpHandle,
  requiredScope = 'mcp:write'
): Promise<ValidationResult[]> {
  const results: ValidationResult[] = [];

  // Mint test tokens
  const validToken = await mockIdp.mintToken({
    audience: mcpUrl,
    scope: `mcp:read ${requiredScope}`,
  });

  const lowScopeToken = await mockIdp.mintToken({
    audience: mcpUrl,
    scope: 'mcp:read',
  });

  const wrongAudToken = await mockIdp.mintToken({
    audience: 'https://example.com',
    scope: `mcp:read ${requiredScope}`,
  });

  const expiredToken = await mockIdp.mintToken({
    audience: mcpUrl,
    scope: `mcp:read ${requiredScope}`,
    expiresIn: '-30s',
  });

  // Mint a token signed by a rogue/untrusted private key
  const { privateKey: rogueKey } = await generateKeyPair('RS256');
  const untrustedSigToken = await new SignJWT({ scope: requiredScope })
    .setProtectedHeader({ alg: 'RS256', kid: 'rogue-key-1' })
    .setIssuer(mockIdp.issuer)
    .setSubject('attacker')
    .setAudience(mcpUrl)
    .setIssuedAt()
    .setExpirationTime('5m')
    .sign(rogueKey);

  // 1. Positive Control: Full MCP SDK v2 Client Handshake & Tool Discovery
  try {
    const client = new Client({
      name: 'mcp-auth-validator',
      version: '0.1.0',
    });

    const transport = new StreamableHTTPClientTransport(new URL(mcpUrl), {
      requestInit: {
        headers: {
          Authorization: `Bearer ${validToken}`,
        },
      },
    });

    await client.connect(transport);
    const tools = await client.listTools();
    await client.close();

    results.push({
      id: 'TOKEN-VALID-SDK-CONNECT',
      name: 'Valid JWT completes MCP v2 client handshake & listTools()',
      status: 'PASS',
      details: `Connected via StreamableHTTPClientTransport and discovered ${tools.tools.length} tool(s).`,
      specRef: 'MCP Spec 2026-07-28 / OAuth 2.1',
    });
  } catch (err) {
    results.push({
      id: 'TOKEN-VALID-SDK-CONNECT',
      name: 'Valid JWT completes MCP v2 client handshake & listTools()',
      status: 'FAIL',
      details: `MCP v2 client failed with valid token: ${err instanceof Error ? err.message : String(err)}`,
      specRef: 'MCP Spec 2026-07-28 / OAuth 2.1',
    });
  }

  // Helper for negative JSON-RPC probes
  const sendProbe = async (headers: Record<string, string>, urlOverride?: string) => {
    return fetch(urlOverride ?? mcpUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json, text/event-stream',
        ...headers,
      },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method: 'tools/list',
      }),
    });
  };

  // 2. Adversarial Probe: Wrong Audience (Confused Deputy / Token Passthrough)
  const wrongAudRes = await sendProbe({
    Authorization: `Bearer ${wrongAudToken}`,
  });
  results.push({
    id: 'TOKEN-AUD-MISMATCH',
    name: 'Rejects valid JWT minted for a different audience (aud)',
    status: wrongAudRes.status === 401 ? 'PASS' : 'FAIL',
    details:
      wrongAudRes.status === 401
        ? 'Correctly rejected wrong-audience token with HTTP 401.'
        : `Security risk: expected HTTP 401 for wrong audience, got HTTP ${wrongAudRes.status}.`,
    specRef: 'RFC 8707 - Resource Indicators',
  });

  // 3. Adversarial Probe: Expired JWT
  const expiredRes = await sendProbe({
    Authorization: `Bearer ${expiredToken}`,
  });
  results.push({
    id: 'TOKEN-EXPIRED',
    name: 'Rejects expired JWT (exp claim)',
    status: expiredRes.status === 401 ? 'PASS' : 'FAIL',
    details:
      expiredRes.status === 401
        ? 'Correctly rejected expired JWT with HTTP 401.'
        : `Expected HTTP 401 for expired JWT, got HTTP ${expiredRes.status}.`,
    specRef: 'RFC 7519 Section 4.1.4',
  });

  // 4. Adversarial Probe: Untrusted Signing Key
  const rogueSigRes = await sendProbe({
    Authorization: `Bearer ${untrustedSigToken}`,
  });
  results.push({
    id: 'TOKEN-INVALID-SIGNATURE',
    name: 'Rejects JWT signed by untrusted key',
    status: rogueSigRes.status === 401 ? 'PASS' : 'FAIL',
    details:
      rogueSigRes.status === 401
        ? 'Correctly rejected untrusted signature with HTTP 401.'
        : `Critical security risk: accepted or mishandled untrusted signature (HTTP ${rogueSigRes.status}).`,
    specRef: 'RFC 7515 - JWS Verification',
  });

  // 5. Adversarial Probe: Query String Bearer Token Rejection
  const queryUrl = new URL(mcpUrl);
  queryUrl.searchParams.set('access_token', validToken);
  const queryRes = await sendProbe({}, queryUrl.toString());
  results.push({
    id: 'TOKEN-QUERY-STRING',
    name: 'Rejects bearer token passed in URL query string',
    status: queryRes.status === 400 || queryRes.status === 401 ? 'PASS' : 'FAIL',
    details:
      queryRes.status === 400 || queryRes.status === 401
        ? `Correctly rejected query-string token with HTTP ${queryRes.status}.`
        : `Security risk: server did not reject query-string token (HTTP ${queryRes.status}).`,
    specRef: 'OAuth 2.1 Section 5.1.2',
  });

  // 6. Step-Up / Insufficient Scope Boundary Check (403 Forbidden)
  const lowScopeRes = await fetch(mcpUrl, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Accept: 'application/json, text/event-stream',
      Authorization: `Bearer ${lowScopeToken}`,
    },
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: 2,
      method: 'tools/call',
      params: { name: '__mcp_auth_validator_privileged_probe__', arguments: {} },
    }),
  });

  const wwwAuth = lowScopeRes.headers.get('www-authenticate') ?? '';
  const hasInsufficientScopeHeader =
    lowScopeRes.status === 403 && wwwAuth.includes('insufficient_scope');

  results.push({
    id: 'TOKEN-INSUFFICIENT-SCOPE',
    name: 'Returns 403 + insufficient_scope header on under-scoped request',
    status:
      lowScopeRes.status === 403
        ? hasInsufficientScopeHeader
          ? 'PASS'
          : 'WARN'
        : 'WARN',
    details:
      lowScopeRes.status === 403
        ? hasInsufficientScopeHeader
          ? 'Returned HTTP 403 with WWW-Authenticate error="insufficient_scope".'
          : 'Returned HTTP 403, but missing error="insufficient_scope" in WWW-Authenticate header.'
        : `Server returned HTTP ${lowScopeRes.status} for low-scope token (configure --scope if server enforces per-tool scopes).`,
    specRef: 'RFC 6750 Section 3.1 / MCP Step-Up Auth',
  });

  return results;
}

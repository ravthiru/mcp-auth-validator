import {
  ProtectedResourceMetadataSchema,
  AuthServerMetadataSchema,
  ValidationResult,
} from '../types.js';

export async function validateDiscoveryAndTransport(
  mcpUrl: string
): Promise<ValidationResult[]> {
  const results: ValidationResult[] = [];

  // 1. Unauthenticated Request -> Must return 401 + WWW-Authenticate
  const unauthRes = await fetch(mcpUrl, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Accept: 'application/json, text/event-stream',
    },
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      method: 'tools/list',
    }),
  });

  const wwwAuth = unauthRes.headers.get('www-authenticate') ?? '';
  const metadataMatch = wwwAuth.match(/resource_metadata="([^"]+)"/);

  if (unauthRes.status !== 401 || !metadataMatch) {
    results.push({
      id: 'AUTH-401-CHALLENGE',
      name: '401 Challenge & resource_metadata header',
      status: 'FAIL',
      details: `Expected HTTP 401 with WWW-Authenticate resource_metadata. Got HTTP ${unauthRes.status} (${wwwAuth || 'no WWW-Authenticate header'}).`,
      specRef: 'RFC 9728 Section 5.1',
    });
    return results;
  }

  const prmUrl = metadataMatch[1];

  results.push({
    id: 'AUTH-401-CHALLENGE',
    name: '401 Challenge & resource_metadata header',
    status: 'PASS',
    details: `Returned HTTP 401 with resource_metadata="${prmUrl}".`,
    specRef: 'RFC 9728 Section 5.1',
  });

  // 2. Fetch & Validate Protected Resource Metadata (PRM)
  let prmJson: unknown;
  try {
    const prmRes = await fetch(prmUrl);
    if (!prmRes.ok) {
      results.push({
        id: 'AUTH-PRM-SCHEMA',
        name: 'Protected Resource Metadata schema',
        status: 'FAIL',
        details: `Failed to fetch PRM from ${prmUrl} (HTTP ${prmRes.status}).`,
        specRef: 'RFC 9728 Section 2',
      });
      return results;
    }
    prmJson = await prmRes.json();
  } catch (err) {
    results.push({
      id: 'AUTH-PRM-SCHEMA',
      name: 'Protected Resource Metadata schema',
      status: 'FAIL',
      details: `Error fetching or parsing PRM JSON from ${prmUrl}: ${err instanceof Error ? err.message : String(err)}`,
      specRef: 'RFC 9728 Section 2',
    });
    return results;
  }

  const parsedPrm = ProtectedResourceMetadataSchema.safeParse(prmJson);
  if (!parsedPrm.success) {
    results.push({
      id: 'AUTH-PRM-SCHEMA',
      name: 'Protected Resource Metadata schema',
      status: 'FAIL',
      details: `Invalid PRM JSON structure: ${parsedPrm.error.issues.map((i) => i.message).join(', ')}`,
      specRef: 'RFC 9728 Section 2',
    });
    return results;
  }

  results.push({
    id: 'AUTH-PRM-SCHEMA',
    name: 'Protected Resource Metadata schema',
    status: 'PASS',
    details: 'Valid RFC 9728 Protected Resource Metadata document.',
    specRef: 'RFC 9728 Section 2',
  });

  // 3. Verify PRM resource matches canonical MCP URL
  const canonicalMatch =
    parsedPrm.data.resource.replace(/\/$/, '') === mcpUrl.replace(/\/$/, '');

  results.push({
    id: 'AUTH-PRM-RESOURCE',
    name: 'PRM resource matches canonical MCP URL',
    status: canonicalMatch ? 'PASS' : 'FAIL',
    details: canonicalMatch
      ? `Resource "${parsedPrm.data.resource}" matches target MCP URL.`
      : `Mismatch: PRM advertises "${parsedPrm.data.resource}", expected "${mcpUrl}".`,
    specRef: 'MCP Authorization Spec - Resource Identifier',
  });

  // 4. Validate Authorization Server Metadata (RFC 8414 / OIDC Discovery)
  const issuer = parsedPrm.data.authorization_servers[0].replace(/\/$/, '');
  const asUrls = [
    `${issuer}/.well-known/oauth-authorization-server`,
    `${issuer}/.well-known/openid-configuration`,
  ];

  let asMetadataValid = false;
  let resolvedAsUrl = '';

  for (const url of asUrls) {
    try {
      const res = await fetch(url);
      if (res.ok) {
        const parsedAs = AuthServerMetadataSchema.safeParse(await res.json());
        if (parsedAs.success) {
          asMetadataValid = true;
          resolvedAsUrl = url;
          break;
        }
      }
    } catch {
      // Try next well-known endpoint
    }
  }

  results.push({
    id: 'AUTH-AS-METADATA',
    name: 'Authorization Server metadata & PKCE S256 support',
    status: asMetadataValid ? 'PASS' : 'FAIL',
    details: asMetadataValid
      ? `Verified AS metadata and S256 PKCE support at ${resolvedAsUrl}.`
      : `Failed to validate AS metadata or missing S256 PKCE support for issuer ${issuer}.`,
    specRef: 'RFC 8414 & OAuth 2.1',
  });

  return results;
}

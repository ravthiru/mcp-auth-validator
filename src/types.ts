import { z } from 'zod';

export type CheckStatus = 'PASS' | 'FAIL' | 'WARN';

export interface ValidationResult {
  id: string;
  name: string;
  status: CheckStatus;
  details: string;
  specRef?: string;
}

// RFC 9728: OAuth 2.0 Protected Resource Metadata
export const ProtectedResourceMetadataSchema = z.object({
  resource: z.string().url(),
  authorization_servers: z.array(z.string().url()).min(1),
  scopes_supported: z.array(z.string()).optional(),
  bearer_methods_supported: z.array(z.string()).optional(),
});

// RFC 8414 / OIDC: Authorization Server Metadata
export const AuthServerMetadataSchema = z.object({
  issuer: z.string().url(),
  authorization_endpoint: z.string().url(),
  token_endpoint: z.string().url(),
  jwks_uri: z.string().url().optional(),
  registration_endpoint: z.string().url().optional(),
  code_challenge_methods_supported: z
    .array(z.string())
    .refine((methods) => methods.includes('S256'), {
      message: 'PKCE S256 must be supported per MCP OAuth 2.1 spec',
    }),
});

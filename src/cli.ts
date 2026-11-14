#!/usr/bin/env node
import { Command } from 'commander';
import { Client } from '@modelcontextprotocol/client';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/client/streamableHttp';
import { validateTransportSecurity } from './validators/transport.js';
import { validateDiscoveryAndTransport } from './validators/discovery.js';
import { validateTokenSecurity } from './validators/tokens.js';
import { startMockIdp } from './mock-idp/server.js';
import { ValidationResult } from './types.js';

const program = new Command();

function printResults(results: ValidationResult[], asJson: boolean): boolean {
  const hasFailures = results.some((r) => r.status === 'FAIL');

  if (asJson) {
    console.log(
      JSON.stringify(
        {
          passed: !hasFailures,
          summary: {
            total: results.length,
            pass: results.filter((r) => r.status === 'PASS').length,
            fail: results.filter((r) => r.status === 'FAIL').length,
            warn: results.filter((r) => r.status === 'WARN').length,
          },
          results,
        },
        null,
        2
      )
    );
    return !hasFailures;
  }

  console.log('\nMCP Authorization Validation Report\n' + '='.repeat(48));
  for (const r of results) {
    const badge =
      r.status === 'PASS' ? '[PASS]' : r.status === 'WARN' ? '[WARN]' : '[FAIL]';
    console.log(`${badge} ${r.id} - ${r.name}`);
    console.log(`       ${r.details}`);
    if (r.specRef) {
      console.log(`       Spec: ${r.specRef}`);
    }
  }
  console.log('='.repeat(48) + '\n');

  return !hasFailures;
}

async function verifyLiveToken(
  mcpUrl: string,
  token: string
): Promise<ValidationResult> {
  try {
    const client = new Client({
      name: 'mcp-auth-validator',
      version: '0.1.0',
    });

    const transport = new StreamableHTTPClientTransport(new URL(mcpUrl), {
      requestInit: {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      },
    });

    await client.connect(transport);
    const tools = await client.listTools();
    await client.close();

    return {
      id: 'TOKEN-LIVE-CONNECT',
      name: 'Custom bearer token completes MCP v2 client handshake',
      status: 'PASS',
      details: `Connected successfully and discovered ${tools.tools.length} tool(s).`,
      specRef: 'MCP Spec 2026-07-28 / OAuth 2.1',
    };
  } catch (err) {
    return {
      id: 'TOKEN-LIVE-CONNECT',
      name: 'Custom bearer token completes MCP v2 client handshake',
      status: 'FAIL',
      details: `Failed to connect with provided token: ${err instanceof Error ? err.message : String(err)}`,
      specRef: 'MCP Spec 2026-07-28 / OAuth 2.1',
    };
  }
}

program
  .name('mcp-auth-validator')
  .description('OAuth 2.1 & security compliance validator for MCP servers')
  .version('0.1.0');

// Command 1: Passive Discovery & Transport Checks
program
  .command('check')
  .description('Run passive discovery, metadata, and transport checks')
  .argument('<mcp-url>', 'Target MCP server endpoint URL')
  .option('--token <jwt>', 'Optional live bearer token to verify handshake')
  .option('--json', 'Output machine-readable JSON report', false)
  .action(
    async (mcpUrl: string, options: { token?: string; json: boolean }) => {
      try {
        const results: ValidationResult[] = [
          ...(await validateTransportSecurity(mcpUrl)),
          ...(await validateDiscoveryAndTransport(mcpUrl)),
        ];

        if (options.token) {
          results.push(await verifyLiveToken(mcpUrl, options.token));
        }

        const passed = printResults(results, options.json);
        process.exit(passed ? 0 : 1);
      } catch (err) {
        console.error(
          'Validation error:',
          err instanceof Error ? err.message : err
        );
        process.exit(1);
      }
    }
  );

// Command 2: Full Adversarial Suite with Mock IdP
program
  .command('test-suite')
  .description('Run full active & adversarial token suite with ephemeral mock IdP')
  .argument('<mcp-url>', 'Target MCP server endpoint URL')
  .option('--idp-port <number>', 'Port for the ephemeral mock IdP', '9999')
  .option('--scope <string>', 'Required scope for privileged calls', 'mcp:write')
  .option('--json', 'Output machine-readable JSON report', false)
  .action(
    async (
      mcpUrl: string,
      options: { idpPort: string; scope: string; json: boolean }
    ) => {
      const port = Number.parseInt(options.idpPort, 10);
      const mockIdp = await startMockIdp(port);

      try {
        const results: ValidationResult[] = [
          ...(await validateTransportSecurity(mcpUrl)),
          ...(await validateDiscoveryAndTransport(mcpUrl)),
          ...(await validateTokenSecurity(mcpUrl, mockIdp, options.scope)),
        ];

        const passed = printResults(results, options.json);
        process.exit(passed ? 0 : 1);
      } catch (err) {
        console.error(
          'Test suite error:',
          err instanceof Error ? err.message : err
        );
        process.exit(1);
      } finally {
        mockIdp.close();
      }
    }
  );

// Command 3: Standalone Mock IdP
program
  .command('mock-idp')
  .description('Start the standalone mock OAuth 2.1 / JWKS server')
  .option('--idp-port <number>', 'Port to bind the mock IdP server', '9999')
  .action(async (options: { idpPort: string }) => {
    const port = Number.parseInt(options.idpPort, 10);
    const mockIdp = await startMockIdp(port);
    console.log(`Mock OAuth 2.1 IdP running at ${mockIdp.issuer}`);
    console.log(`JWKS URI: ${mockIdp.issuer}/.well-known/jwks.json`);
    console.log('Press Ctrl+C to stop.');
  });

program.parse();

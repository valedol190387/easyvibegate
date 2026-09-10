import type { Checker, Finding } from '../../types.js';
import { collectEndpoints } from '../../endpoints.js';

/**
 * Advisory: enumerate the app's HTTP endpoints as targets for the Level 2 live
 * probe. It deliberately does NOT claim any of them lack auth — access checks
 * usually live in middleware, so a static verdict here would be pure noise.
 */
export const routeInventoryChecker: Checker = {
  id: 'route-inventory',
  title: 'Endpoint inventory (targets for live probe)',
  level: 0,
  run(ctx) {
    const endpoints = collectEndpoints(ctx.files);
    if (endpoints.length === 0) return [];

    const preview = endpoints
      .slice(0, 12)
      .map((e) => `${e.method} ${e.path}`)
      .join(', ');
    const more = endpoints.length > 12 ? ` (+${endpoints.length - 12} more)` : '';

    const finding: Finding = {
      id: 'endpoint_inventory',
      severity: 'advisory',
      title: `${endpoints.length} endpoint(s) discovered`,
      detail: `Targets for the Level 2 live probe: ${preview}${more}. Static analysis cannot tell if these enforce access control — run the live probe to confirm.`,
      fix: 'Run VibeGate Level 2 against the running app to test each endpoint without auth and, with two accounts, for cross-user access (IDOR).',
      checker: 'route-inventory',
      level: 0,
    };

    return [finding];
  },
};

import type { Checker } from '../types.js';
import { secretsChecker } from './static/secrets.js';
import { clientExposureChecker } from './static/client-exposure.js';
import { configRisksChecker } from './static/config-risks.js';
import { rlsMigrationsChecker } from './static/rls-migrations.js';
import { envGitChecker } from './static/env-git.js';
import { routeInventoryChecker } from './static/route-inventory.js';

/** Level 0 checkers: read-only static analysis, no install, any stack. */
export const staticCheckers: Checker[] = [
  secretsChecker,
  clientExposureChecker,
  configRisksChecker,
  rlsMigrationsChecker,
  envGitChecker,
  routeInventoryChecker,
];

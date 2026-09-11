import { walk } from './walk.js';
import { detect } from './detect.js';
import { staticCheckers } from './checkers/index.js';
import { applyIgnores, loadConfig } from './config.js';
import type { CheckRun, Detection, Finding, ScanFile } from './types.js';

export interface ScanResult {
  root: string;
  detection: Detection;
  findings: Finding[];
  fileCount: number;
  /** Files collected during the scan — reused by Level 1/2 for discovery. */
  files: ScanFile[];
  /** Execution status of every check that was attempted. */
  runs: CheckRun[];
}

export interface ScanOptions {
  configPath?: string;
}

/** Run all Level 0 (static, read-only) checkers over a project directory. */
export async function scanStatic(root: string, opts: ScanOptions = {}): Promise<ScanResult> {
  const files = walk(root);
  const detection = detect(root, files);
  const ctx = { root, files, detection };

  let findings: Finding[] = [];
  const runs: CheckRun[] = [];
  for (const checker of staticCheckers) {
    try {
      findings.push(...(await checker.run(ctx)));
      runs.push({ id: `static:${checker.id}`, level: 0, status: 'completed' });
    } catch (err) {
      // A broken checker is a failed check, not a clean pass.
      runs.push({
        id: `static:${checker.id}`,
        level: 0,
        status: 'failed',
        note: err instanceof Error ? err.message : String(err),
      });
    }
  }

  const config = loadConfig(root, opts.configPath);
  findings = applyIgnores(findings, config, files);

  return { root, detection, findings, fileCount: files.length, files, runs };
}

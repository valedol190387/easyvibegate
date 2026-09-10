import { walk } from './walk.js';
import { detect } from './detect.js';
import { staticCheckers } from './checkers/index.js';
import { applyIgnores, loadConfig } from './config.js';
import type { Detection, Finding, ScanFile } from './types.js';

export interface ScanResult {
  root: string;
  detection: Detection;
  findings: Finding[];
  fileCount: number;
  /** Files collected during the scan — reused by Level 1/2 for discovery. */
  files: ScanFile[];
}

export interface ScanOptions {
  configPath?: string;
}

/** Run all Level 0 (static, read-only) checkers over a project directory. */
export async function scanStatic(root: string, opts: ScanOptions = {}): Promise<ScanResult> {
  const files = walk(root);
  const detection = detect(files);
  const ctx = { root, files, detection };

  let findings: Finding[] = [];
  for (const checker of staticCheckers) {
    try {
      findings.push(...(await checker.run(ctx)));
    } catch (err) {
      findings.push({
        id: 'checker_error',
        severity: 'info',
        title: `Checker "${checker.id}" failed`,
        detail: err instanceof Error ? err.message : String(err),
        fix: 'Please report this at the EasyVibeGate repository.',
        checker: checker.id,
        level: checker.level,
      });
    }
  }

  const config = loadConfig(root, opts.configPath);
  findings = applyIgnores(findings, config, files);

  return { root, detection, findings, fileCount: files.length, files };
}

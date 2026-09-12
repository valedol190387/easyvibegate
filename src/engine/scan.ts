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
  /** Absolute directories to leave out of the walk (the report directory). */
  excludeAbs?: string[];
}

/** Run all Level 0 (static, read-only) checkers over a project directory. */
export async function scanStatic(root: string, opts: ScanOptions = {}): Promise<ScanResult> {
  const { files, skippedOversized, skippedUnreadable, skippedDirs, skippedSymlinks } = walk(root, { excludeAbs: opts.excludeAbs });
  const detection = detect(root, files);
  const ctx = { root, files, detection };

  let findings: Finding[] = [];
  const runs: CheckRun[] = [];

  // Zero scannable files means nothing was actually reviewed — record it as a
  // failed precondition, and mark the static checkers as skipped (they had no
  // input), so the result is never shown as a clean, well-covered 100/100.
  if (files.length === 0) {
    runs.push({ id: 'walk', level: 0, status: 'failed', note: 'no scannable files found at this path' });
    for (const checker of staticCheckers) {
      runs.push({ id: `static:${checker.id}`, level: 0, status: 'skipped', note: 'no files to check' });
    }
    return { root, detection, findings, fileCount: 0, files, runs };
  }

  // Files we could not read are missing coverage, not a clean result.
  const lost = skippedOversized + skippedUnreadable + skippedDirs + skippedSymlinks;
  if (lost > 0) {
    const parts: string[] = [];
    if (skippedOversized) parts.push(`${skippedOversized} file(s) over the 1 MB limit`);
    if (skippedUnreadable) parts.push(`${skippedUnreadable} unreadable file(s)`);
    if (skippedDirs) parts.push(`${skippedDirs} unreadable director(y/ies) — their whole subtree went unchecked`);
    if (skippedSymlinks) parts.push(`${skippedSymlinks} symlink(s) skipped — their targets were not scanned`);
    runs.push({ id: 'walk', level: 0, status: 'partial', note: `not scanned: ${parts.join(', ')}` });
  }

  for (const checker of staticCheckers) {
    try {
      const res = await checker.run(ctx);
      const { findings: got, partial } = Array.isArray(res) ? { findings: res, partial: undefined } : res;
      findings.push(...got);
      // A checker that could not interpret part of its input did not fully run.
      runs.push(
        partial
          ? { id: `static:${checker.id}`, level: 0, status: 'partial', note: partial }
          : { id: `static:${checker.id}`, level: 0, status: 'completed' },
      );
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
  if (config.problem) {
    runs.push({ id: 'config', level: 0, status: 'failed', note: `${config.problem} — suppression rules were NOT applied` });
  }
  findings = applyIgnores(findings, config, files);

  return { root, detection, findings, fileCount: files.length, files, runs };
}

/**
 * Blank out comments (and, optionally, quoted strings) while preserving length
 * and newlines, so match offsets and line numbers stay correct. Used so that a
 * comment like `// never use eval()` is not reported as a finding.
 */
export function maskCode(src: string, opts: { strings?: boolean } = {}): string {
  const out = src.split('');
  const n = src.length;
  const blank = (from: number, to: number) => {
    for (let k = from; k < to && k < n; k++) if (out[k] !== '\n') out[k] = ' ';
  };
  let i = 0;
  while (i < n) {
    const ch = src[i];
    const next = src[i + 1];
    if (ch === '/' && next === '/') { let j = i; while (j < n && src[j] !== '\n') j++; blank(i, j); i = j; continue; }
    if (ch === '#' && src[i - 1] !== '$') { let j = i; while (j < n && src[j] !== '\n') j++; blank(i, j); i = j; continue; }
    if (ch === '/' && next === '*') { const c = src.indexOf('*/', i + 2); const end = c === -1 ? n : c + 2; blank(i, end); i = end; continue; }
    if (opts.strings && (ch === '"' || ch === "'")) {
      let j = i + 1;
      while (j < n && src[j] !== ch) { if (src[j] === '\\') j++; if (src[j] === '\n') break; j++; }
      const end = Math.min(j + 1, n); blank(i, end); i = end; continue;
    }
    i++;
  }
  return out.join('');
}

/** Minified/bundled output is not source a human wrote — reviewing it is noise. */
export function looksMinified(rel: string, content: string): boolean {
  if (/\.min\.(js|css|mjs|cjs)$/i.test(rel) || /(^|\/)(dist|build|vendor|bundle)\//.test(rel)) return true;
  const lines = content.split('\n');
  const longest = lines.reduce((m, l) => Math.max(m, l.length), 0);
  return longest > 800 && lines.length < content.length / 200;
}

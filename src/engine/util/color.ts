const enabled =
  !!process.stdout.isTTY &&
  process.env['NO_COLOR'] === undefined &&
  process.env['TERM'] !== 'dumb';

function wrap(code: number) {
  return (s: string) => (enabled ? `\x1b[${code}m${s}\x1b[0m` : s);
}

export const color = {
  enabled,
  red: wrap(31),
  green: wrap(32),
  yellow: wrap(33),
  blue: wrap(34),
  cyan: wrap(36),
  gray: wrap(90),
  bold: wrap(1),
  dim: wrap(2),
};

export interface ParsedArgs { command: string; positionals: string[]; flags: Record<string, string | boolean>; }

export function parseArgs(argv: string[]): ParsedArgs {
  const command = argv[0] && !argv[0].startsWith("-") ? argv[0] : "scan";
  const rest = command === "scan" && argv[0]?.startsWith("-") ? argv : argv.slice(1);
  const positionals: string[] = [];
  const flags: Record<string, string | boolean> = {};
  for (let index = 0; index < rest.length; index += 1) {
    const token = rest[index] ?? "";
    if (token === "-h") { flags.help = true; continue; }
    if (token === "-v") { flags.version = true; continue; }
    if (!token.startsWith("--")) { positionals.push(token); continue; }
    const [rawName = "", inline] = token.slice(2).split("=", 2);
    const name = rawName.startsWith("no-") ? rawName.slice(3) : rawName;
    if (rawName.startsWith("no-")) { flags[name] = false; continue; }
    if (inline !== undefined) { flags[name] = inline; continue; }
    const next = rest[index + 1];
    if (next && !next.startsWith("--")) { flags[name] = next; index += 1; }
    else flags[name] = true;
  }
  return { command, positionals, flags };
}

export function stringFlag(flags: Record<string, string | boolean>, name: string): string | undefined {
  const value = flags[name];
  return typeof value === "string" ? value : undefined;
}

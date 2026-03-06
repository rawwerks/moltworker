import * as fs from "fs";
import * as path from "path";

interface BootstrapFile {
  name: string;
  path: string;
  content?: string;
  missing: boolean;
}

interface HookEvent {
  type: string;
  action: string;
  context: {
    bootstrapFiles?: BootstrapFile[];
    workspaceDir?: string;
  };
}

const DIRPACK_PATHS = [
  "/root/clawd/skills/source-index/DIRPACK.md",
  "/root/clawd/DIRPACK.md",
];

function getDirpackContent(): string {
  for (const p of DIRPACK_PATHS) {
    try {
      if (fs.existsSync(p)) {
        return fs.readFileSync(p, "utf-8");
      }
    } catch {
      // try next
    }
  }
  return "";
}

export default async function sourceIndexHook(event: HookEvent): Promise<void> {
  if (event.type !== "agent" || event.action !== "bootstrap") return;

  const context = event.context;
  if (!Array.isArray(context.bootstrapFiles)) return;

  const content = getDirpackContent();
  if (!content) return;

  const dirpackFile: BootstrapFile = {
    name: "DIRPACK.md",
    path: DIRPACK_PATHS[0],
    content: `# Moltworker Source Index\n\nThis is the source code map of the moltworker infrastructure that runs you.\n\n${content}`,
    missing: false,
  };

  context.bootstrapFiles.push(dirpackFile);
}

import * as fs from "fs";
import * as path from "path";
const DIRPACK_PATHS = [
  "/root/clawd/skills/source-index/DIRPACK.md",
  "/root/clawd/DIRPACK.md",
  "/root/clawd/hooks/source-index/DIRPACK.md"
];
function getDirpackContent() {
  for (const p of DIRPACK_PATHS) {
    try {
      if (fs.existsSync(p)) {
        return fs.readFileSync(p, "utf-8");
      }
    } catch {
    }
  }
  return "";
}
async function sourceIndexHook(event) {
  if (event.type !== "agent" || event.action !== "bootstrap") return;
  const context = event.context;
  if (!Array.isArray(context.bootstrapFiles)) return;
  const content = getDirpackContent();
  if (!content) return;
  const dirpackFile = {
    name: "DIRPACK.md",
    path: DIRPACK_PATHS[0],
    content: "# Moltworker Source Index\n\nThis is the source code map of the moltworker infrastructure that runs you.\n\n" + content,
    missing: false
  };
  const identityIndex = context.bootstrapFiles.findIndex((f) => f.name === "IDENTITY.md");
  if (identityIndex >= 0) {
    context.bootstrapFiles.splice(identityIndex + 1, 0, dirpackFile);
  } else {
    context.bootstrapFiles.push(dirpackFile);
  }
}
export {
  sourceIndexHook as default
};

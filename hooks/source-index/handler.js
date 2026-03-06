import * as fs from "fs";
const DIRPACK_PATH = "/root/clawd/DIRPACK.md";
function getDirpackContent() {
  try {
    if (fs.existsSync(DIRPACK_PATH)) {
      return fs.readFileSync(DIRPACK_PATH, "utf-8");
    }
  } catch {
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
    path: DIRPACK_PATH,
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

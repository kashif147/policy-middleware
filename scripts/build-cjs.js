const fs = require("fs");
const path = require("path");

const srcDir = path.join(__dirname, "..", "src");
const distDir = path.join(__dirname, "..", "dist");

// Create dist directory
if (!fs.existsSync(distDir)) {
  fs.mkdirSync(distDir, { recursive: true });
}

// Copy all .js files from src to dist (they're already CommonJS)
function copyFiles(src, dest) {
  if (!fs.existsSync(dest)) {
    fs.mkdirSync(dest, { recursive: true });
  }

  const entries = fs.readdirSync(src, { withFileTypes: true });

  for (const entry of entries) {
    const srcPath = path.join(src, entry.name);
    const destPath = path.join(dest, entry.name);

    if (entry.isDirectory()) {
      copyFiles(srcPath, destPath);
    } else if (entry.name.endsWith(".js")) {
      fs.copyFileSync(srcPath, destPath);
    }
  }
}

copyFiles(srcDir, distDir);

console.log("✅ CommonJS build completed");


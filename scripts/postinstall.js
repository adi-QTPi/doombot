'use strict';

const fs = require('node:fs');
const path = require('node:path');

const prebuilds = path.join(__dirname, '..', 'node_modules', 'node-pty', 'prebuilds');
if (!fs.existsSync(prebuilds)) process.exit(0);

for (const dir of fs.readdirSync(prebuilds)) {
  const helper = path.join(prebuilds, dir, 'spawn-helper');
  if (fs.existsSync(helper) && !(fs.statSync(helper).mode & 0o111)) {
    fs.chmodSync(helper, 0o755);
    console.log(`fixed exec bit on ${path.relative(process.cwd(), helper)}`);
  }
}

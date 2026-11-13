import { cp, mkdir } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
const source = path.dirname(fileURLToPath(import.meta.url));
const output = path.resolve(process.argv[2] || path.join(source, '../dist/browser-extension'));
if (output === source || source.startsWith(output + path.sep)) throw new Error('Output must not contain extension sources');
const files = ['policy.js','i18n.js','controller.js','background.js','popup.html','popup.js','blocked.html','blocked.js','ui.css','rules.json','icon.png'];
for (const [browser, manifest] of [['chromium','manifest.json'],['firefox','manifest.firefox.json']]) {
  const dir = path.join(output, browser);
  await mkdir(dir, {recursive:true});
  // Only replace our known package files, never remove an arbitrary user directory.
  for (const name of files) await cp(path.join(source,name),path.join(dir,name));
  await cp(path.join(source,manifest),path.join(dir,'manifest.json'));
  await cp(path.join(source,'_locales'),path.join(dir,'_locales'),{recursive:true});
}
console.log(output);

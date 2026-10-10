import { spawn } from 'child_process';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

function runScript(scriptName) {
  return new Promise((resolve, reject) => {
    console.log(`\n======================================================`);
    console.log(`[+] Launching: ${scriptName}`);
    console.log(`======================================================\n`);
    const proc = spawn('node', [scriptName], {
      cwd: __dirname,
      stdio: 'inherit'
    });
    proc.on('close', (code) => {
      if (code === 0) {
        console.log(`\n[✓] Successfully finished ${scriptName}\n`);
        resolve();
      } else {
        console.error(`\n[!] Error in ${scriptName}, exited with code ${code}\n`);
        reject(new Error(`Failed ${scriptName}`));
      }
    });
  });
}

async function main() {
  console.log("Starting automated generation of Video 04 and Video 05...");
  await runScript('generate_video_04.js');
  await runScript('generate_video_05.js');
  console.log("\n[🎉] Videos 04 and 05 generated successfully!\n");
}

main().catch(console.error);

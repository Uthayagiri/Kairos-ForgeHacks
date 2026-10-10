import puppeteer from 'puppeteer';
import { spawn } from 'child_process';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const FFMPEG_PATH = "C:\\Users\\Udhaya\\S5_Phishing_Detector\\backend\\venv\\Lib\\site-packages\\imageio_ffmpeg\\binaries\\ffmpeg-win-x86_64-v7.1.exe";

async function testVideoPipe() {
  console.log("Testing video pipe with FFmpeg:", FFMPEG_PATH);
  const outputPath = path.resolve(__dirname, '../forgehacks_submission/videos/test_pipe.mp4');
  
  const ffmpeg = spawn(FFMPEG_PATH, [
    '-y',
    '-f', 'image2pipe',
    '-vcodec', 'png',
    '-r', '30',
    '-i', '-',
    '-c:v', 'libx264',
    '-pix_fmt', 'yuv420p',
    '-preset', 'ultrafast',
    '-crf', '20',
    outputPath
  ]);

  ffmpeg.stderr.on('data', (d) => {
    // console.log(`ffmpeg: ${d}`);
  });

  const browser = await puppeteer.launch({
    headless: 'new',
    args: ['--no-sandbox', '--disable-setuid-sandbox']
  });

  const page = await browser.newPage();
  await page.setViewport({ width: 1920, height: 1080 });

  // Render 60 frames (2 seconds)
  for (let i = 0; i < 60; i++) {
    const hue = (i * 6) % 360;
    const html = `
      <!DOCTYPE html>
      <html>
      <body style="margin:0; background:#0B101B; display:flex; flex-direction:column; align-items:center; justify-content:center; height:100vh; font-family:sans-serif; color:white;">
        <h1 style="color:hsl(${hue}, 80%, 60%); font-size:48px;">PhishGuard AI Video Pipeline Test</h1>
        <p style="font-size:24px; color:#94A3B8;">Frame ${i + 1} of 60 (30 FPS 1080p)</p>
      </body>
      </html>
    `;
    await page.setContent(html, { waitUntil: 'domcontentloaded' });
    const buffer = await page.screenshot({ type: 'png' });
    ffmpeg.stdin.write(buffer);
  }

  ffmpeg.stdin.end();
  await browser.close();

  await new Promise((resolve) => {
    ffmpeg.on('close', (code) => {
      console.log(`FFmpeg exited with code ${code}. Video saved to ${outputPath}`);
      resolve();
    });
  });
}

testVideoPipe().catch(console.error);

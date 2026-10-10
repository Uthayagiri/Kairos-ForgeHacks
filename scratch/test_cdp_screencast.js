import puppeteer from 'puppeteer';
import { spawn } from 'child_process';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const FFMPEG_PATH = "C:\\Users\\Udhaya\\S5_Phishing_Detector\\backend\\venv\\Lib\\site-packages\\imageio_ffmpeg\\binaries\\ffmpeg-win-x86_64-v7.1.exe";

async function testCDPScreencast() {
  console.log("Testing CDP Screencast recording...");
  const outputPath = path.resolve(__dirname, '../forgehacks_submission/videos/test_cdp.mp4');

  const ffmpeg = spawn(FFMPEG_PATH, [
    '-y',
    '-f', 'image2pipe',
    '-vcodec', 'mjpeg',
    '-r', '30',
    '-i', '-',
    '-c:v', 'libx264',
    '-pix_fmt', 'yuv420p',
    '-preset', 'veryfast',
    '-crf', '18',
    outputPath
  ]);

  ffmpeg.stderr.on('data', (d) => {
    // console.log(`ffmpeg: ${d}`);
  });

  const browser = await puppeteer.launch({
    headless: 'new',
    args: [
      '--no-sandbox',
      '--disable-setuid-sandbox',
      '--window-size=1920,1080',
      '--enable-features=NetworkService,NetworkServiceInProcess'
    ]
  });

  const page = await browser.newPage();
  await page.setViewport({ width: 1920, height: 1080 });

  const client = await page.target().createCDPSession();

  let frameCount = 0;
  client.on('Page.screencastFrame', async ({ data, sessionId }) => {
    try {
      ffmpeg.stdin.write(Buffer.from(data, 'base64'));
      frameCount++;
      await client.send('Page.screencastFrameAck', { sessionId });
    } catch (e) {}
  });

  await client.send('Page.startScreencast', {
    format: 'jpeg',
    quality: 95,
    maxWidth: 1920,
    maxHeight: 1080,
    everyNthFrame: 1
  });

  // Navigate to live app
  await page.goto('http://localhost:5173/', { waitUntil: 'domcontentloaded' });
  await new Promise(r => setTimeout(r, 4000));

  await client.send('Page.stopScreencast');
  ffmpeg.stdin.end();

  await browser.close();

  await new Promise((resolve) => {
    ffmpeg.on('close', (code) => {
      console.log(`CDP test done. Frames: ${frameCount}, Code: ${code}`);
      resolve();
    });
  });
}

testCDPScreencast().catch(console.error);

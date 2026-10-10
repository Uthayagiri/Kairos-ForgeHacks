import puppeteer from 'puppeteer';
import { spawn } from 'child_process';
import path from 'path';
import { fileURLToPath } from 'url';
import fs from 'fs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const FFMPEG_PATH = "C:\\Users\\Udhaya\\S5_Phishing_Detector\\backend\\venv\\Lib\\site-packages\\imageio_ffmpeg\\binaries\\ffmpeg-win-x86_64-v7.1.exe";
const VIDEOS_DIR = path.resolve(__dirname, '../forgehacks_submission/videos');

if (!fs.existsSync(VIDEOS_DIR)) {
  fs.mkdirSync(VIDEOS_DIR, { recursive: true });
}

// Helper to ease in-out
function easeInOutQuad(t) {
  return t < 0.5 ? 2 * t * t : -1 + (4 - 2 * t) * t;
}

// Base CSS styles shared across all frames
const BASE_STYLES = `
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    background-color: #070B14;
    color: #F1F5F9;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
    width: 1920px;
    height: 1080px;
    overflow: hidden;
    position: relative;
    display: flex;
    flex-direction: column;
  }
  .glass-card {
    background: rgba(15, 23, 42, 0.75);
    backdrop-filter: blur(16px);
    border: 1px solid rgba(51, 65, 85, 0.6);
    border-radius: 14px;
  }
  .navbar {
    height: 70px;
    padding: 0 40px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    background: rgba(11, 16, 27, 0.95);
    border-bottom: 1px solid #1E293B;
  }
  .logo {
    display: flex;
    align-items: center;
    gap: 12px;
    font-size: 22px;
    font-weight: 800;
    letter-spacing: -0.5px;
  }
  .badge-online {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    padding: 6px 14px;
    border-radius: 9999px;
    font-size: 13px;
    font-weight: 600;
    background: rgba(16, 185, 129, 0.12);
    border: 1px solid rgba(16, 185, 129, 0.35);
    color: #10B981;
  }
  .badge-dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: #10B981;
    box-shadow: 0 0 8px #10B981;
  }
  .caption-bar {
    position: absolute;
    bottom: 0;
    left: 0;
    right: 0;
    height: 80px;
    background: rgba(3, 7, 18, 0.92);
    border-top: 1px solid #1E293B;
    display: flex;
    align-items: center;
    padding: 0 40px;
    gap: 20px;
    z-index: 100;
  }
  .caption-tag {
    background: #3B82F6;
    color: #FFFFFF;
    font-weight: 700;
    font-size: 12px;
    letter-spacing: 0.5px;
    text-transform: uppercase;
    padding: 6px 12px;
    border-radius: 6px;
  }
  .caption-text {
    font-size: 18px;
    color: #E2E8F0;
    font-weight: 500;
  }
  .cursor-pointer {
    position: absolute;
    width: 24px;
    height: 24px;
    pointer-events: none;
    z-index: 999;
    filter: drop-shadow(0 2px 4px rgba(0,0,0,0.5));
  }
`;

function renderCursorSvg(x, y, clicking = false) {
  return `
    <div class="cursor-pointer" style="left: ${x}px; top: ${y}px; transform: scale(${clicking ? '0.85' : '1.0'}); transition: transform 0.1s;">
      <svg width="24" height="24" viewBox="0 0 24 24" fill="none">
        <path d="M5.5 3.21V20.8c0 .45.54.67.85.35l4.86-4.86a.5.5 0 0 1 .35-.15h6.87c.45 0 .67-.54.35-.85L5.85 2.35c-.32-.32-.85-.1-.85.36z" fill="#3B82F6" stroke="#FFFFFF" stroke-width="1.5"/>
      </svg>
    </div>
  `;
}

console.log("Video generator module initialized. Output dir:", VIDEOS_DIR);
export { FFMPEG_PATH, VIDEOS_DIR, BASE_STYLES, renderCursorSvg, easeInOutQuad };

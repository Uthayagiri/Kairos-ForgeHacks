import puppeteer from 'puppeteer';
import { spawn } from 'child_process';
import path from 'path';
import { fileURLToPath } from 'url';
import { FFMPEG_PATH, VIDEOS_DIR, BASE_STYLES, renderCursorSvg, easeInOutQuad } from './video_helpers.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function generateVideo03() {
  const outputPath = path.join(VIDEOS_DIR, '03_extension_url_scanning.mp4');
  console.log(`[+] Starting generation of: ${outputPath}`);

  const FPS = 30;
  const DURATION_SEC = 60;
  const TOTAL_FRAMES = FPS * DURATION_SEC; // 1800 frames

  const ffmpeg = spawn(FFMPEG_PATH, [
    '-y',
    '-f', 'image2pipe',
    '-vcodec', 'png',
    '-r', String(FPS),
    '-i', '-',
    '-c:v', 'libx264',
    '-pix_fmt', 'yuv420p',
    '-preset', 'ultrafast',
    '-crf', '19',
    outputPath
  ]);

  const browser = await puppeteer.launch({
    headless: 'new',
    args: ['--no-sandbox', '--disable-setuid-sandbox']
  });

  const page = await browser.newPage();
  await page.setViewport({ width: 1920, height: 1080 });

  for (let frame = 0; frame < TOTAL_FRAMES; frame++) {
    const tSec = frame / FPS;

    let tabIndex = 1; // 1: safe (0-20s), 2: suspicious (20-40s), 3: high-risk (40-60s)
    let url = '';
    let pageTitle = '';
    let verdictLabel = '';
    let riskScore = '';
    let themeColor = '#10B981';
    let badgeText = 'OK';
    let cursorX = 960;
    let cursorY = 800;
    let captionTag = '';
    let captionText = '';

    if (tSec < 20) {
      tabIndex = 1;
      url = 'https://docs.python.org/3/library/index.html';
      pageTitle = 'Python 3 Standard Library Documentation';
      verdictLabel = 'SAFE / BENIGN';
      riskScore = '0.4%';
      themeColor = '#10B981';
      badgeText = 'OK';
      captionTag = 'EXTENSION: SAFE TAB';
      captionText = 'Active Tab 1: Python Docs. Extension popup verifies TLS 1.3, 0 threats, and 0.4% low risk score.';
      cursorX = 1600 + Math.sin(tSec) * 40;
      cursorY = 400 + Math.cos(tSec) * 40;
    } else if (tSec < 40) {
      tabIndex = 2;
      url = 'http://unverified-fast-news.biz/article/2026';
      pageTitle = 'Breaking Global News - Unverified Portal';
      verdictLabel = 'SUSPICIOUS DOMAIN';
      riskScore = '48.0%';
      themeColor = '#F59E0B';
      badgeText = '48%';
      captionTag = 'EXTENSION: SUSPICIOUS TAB';
      captionText = 'Active Tab 2: Unverified News. Extension displays amber badge (48.0% risk) due to plain HTTP and .biz TLD.';
      cursorX = 1600 + Math.sin(tSec - 20) * 40;
      cursorY = 400 + Math.cos(tSec - 20) * 40;
    } else {
      tabIndex = 3;
      url = 'http://192.168.1.50/secure-login/account-verification';
      pageTitle = 'Secure Account Verification - Urgent Login';
      verdictLabel = 'CRITICAL PHISHING THREAT';
      riskScore = '91.1%';
      themeColor = '#EF4444';
      badgeText = '91%';
      captionTag = 'EXTENSION: CRITICAL THREAT';
      captionText = 'Active Tab 3: SSRF Phishing Lure. Extension flags raw IP obfuscation and credential keywords (91.1% risk).';
      cursorX = 1600 + Math.sin(tSec - 40) * 40;
      cursorY = 400 + Math.cos(tSec - 40) * 40;
    }

    const html = `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <style>
          ${BASE_STYLES}
          .browser-window {
            margin: 20px 40px;
            height: 940px;
            background: #0B101B;
            border-radius: 12px;
            border: 1px solid #1E293B;
            display: flex;
            flex-direction: column;
            overflow: hidden;
            box-shadow: 0 25px 50px rgba(0,0,0,0.8);
            position: relative;
          }
          .browser-topbar {
            background: #0F172A;
            border-bottom: 1px solid #1E293B;
            padding: 10px 16px;
            display: flex;
            align-items: center;
            gap: 16px;
          }
          .tab-strip {
            display: flex;
            gap: 8px;
          }
          .browser-tab {
            padding: 8px 16px;
            border-radius: 8px 8px 0 0;
            font-size: 13px;
            display: flex;
            align-items: center;
            gap: 8px;
            max-width: 220px;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
          }
          .tab-active {
            background: #1E293B;
            color: #F8FAFC;
            font-weight: 600;
            border-top: 2px solid ${themeColor};
          }
          .tab-inactive {
            background: rgba(15, 23, 42, 0.5);
            color: #64748B;
          }
          .browser-omnibox {
            background: #030712;
            border: 1px solid #334155;
            border-radius: 8px;
            padding: 8px 14px;
            display: flex;
            align-items: center;
            gap: 10px;
            flex: 1;
            font-family: monospace;
            font-size: 14px;
          }
          .extension-popup-container {
            position: absolute;
            top: 70px;
            right: 40px;
            width: 440px;
            background: rgba(11, 16, 27, 0.96);
            border: 1px solid ${themeColor};
            border-radius: 16px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.8), 0 0 20px ${themeColor}33;
            z-index: 50;
            overflow: hidden;
            display: flex;
            flex-direction: column;
          }
        </style>
      </head>
      <body>
        <div class="browser-window">
          <!-- Top Bar with Tabs and Controls -->
          <div class="browser-topbar">
            <!-- Mac window buttons -->
            <div style="display:flex; gap: 6px;">
              <span style="width:12px; height:12px; border-radius:50%; background:#EF4444;"></span>
              <span style="width:12px; height:12px; border-radius:50%; background:#F59E0B;"></span>
              <span style="width:12px; height:12px; border-radius:50%; background:#10B981;"></span>
            </div>

            <!-- Tab strip -->
            <div class="tab-strip">
              <div class="browser-tab ${tabIndex === 1 ? 'tab-active' : 'tab-inactive'}">
                <span>🐍</span>
                <span>Python Documentation</span>
              </div>
              <div class="browser-tab ${tabIndex === 2 ? 'tab-active' : 'tab-inactive'}">
                <span>📰</span>
                <span>unverified-fast-news.biz</span>
              </div>
              <div class="browser-tab ${tabIndex === 3 ? 'tab-active' : 'tab-inactive'}">
                <span>🚨</span>
                <span>192.168.1.50/secure-login</span>
              </div>
            </div>

            <!-- Omnibox URL -->
            <div class="browser-omnibox">
              <span style="color: ${themeColor}; font-size: 16px;">${tabIndex === 1 ? '🔒' : (tabIndex === 2 ? '⚠️' : '🚫')}</span>
              <span style="color: ${tabIndex === 1 ? '#10B981' : (tabIndex === 2 ? '#F59E0B' : '#EF4444')};">${url}</span>
            </div>

            <!-- Extension icon in toolbar -->
            <div style="background: ${themeColor}22; border: 1px solid ${themeColor}66; border-radius: 8px; padding: 6px 12px; display:flex; align-items:center; gap: 8px; font-weight:700; font-size:13px; color:${themeColor};">
              <span>🛡️ PhishGuard AI</span>
              <span style="background: ${themeColor}; color: ${themeColor === '#10B981' ? '#000' : '#FFF'}; font-size: 11px; padding: 2px 6px; border-radius: 4px; font-weight: 800;">${badgeText}</span>
            </div>
          </div>

          <!-- Browser Tab Page Content -->
          <div style="flex:1; background: #FFFFFF; color: #1E293B; padding: 40px 60px; font-family: sans-serif; overflow:hidden;">
            <div style="max-width: 900px;">
              <div style="font-size: 14px; color: #64748B; margin-bottom: 8px;">${url}</div>
              <h1 style="font-size: 36px; font-weight: 800; color: #0F172A; margin-bottom: 20px;">${pageTitle}</h1>
              <p style="font-size: 18px; color: #475569; line-height: 1.6; margin-bottom: 24px;">
                ${tabIndex === 1 
                  ? 'The Python Standard Library contains the exact syntax and semantics of the standard modules and built-in functions included with every distribution.'
                  : (tabIndex === 2 
                    ? 'Latest breaking updates on international trade and global economic developments. Fast unverified syndicated coverage.' 
                    : '<strong style="color:#DC2626;">URGENT NOTICE:</strong> Your account requires immediate verification. Enter your administrator username and password below to prevent account suspension.')}
              </p>
              ${tabIndex === 3 ? `
                <div style="background: #FEE2E2; border: 1px solid #FCA5A5; border-radius: 8px; padding: 20px; max-width: 500px;">
                  <div style="font-weight: 700; color: #991B1B; margin-bottom: 10px;">Account Login Verification</div>
                  <input placeholder="Username / Email" style="width:100%; padding:10px; margin-bottom:10px; border:1px solid #CBD5E1; border-radius:6px;" disabled />
                  <input placeholder="Password" type="password" style="width:100%; padding:10px; margin-bottom:10px; border:1px solid #CBD5E1; border-radius:6px;" disabled />
                  <button style="background:#DC2626; color:white; border:none; padding:10px 20px; border-radius:6px; font-weight:700;" disabled>Sign In & Verify</button>
                </div>
              ` : ''}
            </div>
          </div>

          <!-- PhishGuard AI Extension Popup (Floating Right) -->
          <div class="extension-popup-container">
            <!-- Popup Header -->
            <div style="background: #0F172A; padding: 16px 20px; border-bottom: 1px solid #1E293B; display:flex; justify-content:space-between; align-items:center;">
              <div style="display:flex; align-items:center; gap: 8px; font-weight:800; font-size:16px;">
                <span>🛡️</span>
                <span>PhishGuard <span style="color: #3B82F6;">AI</span></span>
              </div>
              <div style="font-size: 11px; font-weight:700; color: #10B981; background: rgba(16,185,129,0.1); padding: 3px 8px; border-radius: 999px; border: 1px solid rgba(16,185,129,0.3);">
                Backend Online
              </div>
            </div>

            <!-- Popup Body -->
            <div style="padding: 20px;">
              <div style="font-size: 11px; color: #94A3B8; text-transform:uppercase; font-weight:700; margin-bottom: 4px;">Active Tab Inspection</div>
              <div style="background: rgba(30,41,59,0.6); border: 1px solid #334155; border-radius: 6px; padding: 8px 12px; font-family:monospace; font-size:12px; color:#F8FAFC; margin-bottom: 16px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">
                ${url}
              </div>

              <!-- Verdict Box -->
              <div style="background: ${themeColor}15; border: 1px solid ${themeColor}44; border-radius: 10px; padding: 16px; display:flex; justify-content:space-between; align-items:center; margin-bottom: 16px;">
                <div>
                  <div style="font-size: 10px; font-weight:800; color:${themeColor}; letter-spacing:1px; text-transform:uppercase;">VERDICT</div>
                  <div style="font-size: 18px; font-weight:800; color:#FFFFFF;">${verdictLabel}</div>
                </div>
                <div style="text-align:right;">
                  <div style="font-size: 26px; font-weight:900; color:${themeColor}; font-family:monospace;">${riskScore}</div>
                  <div style="font-size: 9px; color:#94A3B8; font-weight:700;">RISK SCORE</div>
                </div>
              </div>

              <!-- Metrics Mini Grid -->
              <div style="display:grid; grid-template-columns: 1fr 1fr; gap: 10px; margin-bottom: 16px;">
                <div style="background: rgba(30,41,59,0.4); border:1px solid #334155; padding:10px; border-radius:6px;">
                  <div style="font-size: 10px; color:#94A3B8; font-weight:700;">HTTPS SECURITY</div>
                  <div style="font-size: 12px; font-weight:700; color:${tabIndex === 1 ? '#10B981' : '#EF4444'};">
                    ${tabIndex === 1 ? 'TLS 1.3 Verified' : 'Insecure Plain HTTP'}
                  </div>
                </div>
                <div style="background: rgba(30,41,59,0.4); border:1px solid #334155; padding:10px; border-radius:6px;">
                  <div style="font-size: 10px; color:#94A3B8; font-weight:700;">SSRF BOUNDARY</div>
                  <div style="font-size: 12px; font-weight:700; color:${tabIndex === 3 ? '#EF4444' : '#10B981'};">
                    ${tabIndex === 3 ? 'BLOCKED (Private IP)' : 'Passed (Clean)'}
                  </div>
                </div>
              </div>

              <!-- Quick Action Button -->
              <div style="display:flex; gap: 10px;">
                <button style="flex:1; background: #3B82F6; color:white; border:none; padding:10px; border-radius:8px; font-size:13px; font-weight:700; cursor:pointer;">
                  🔄 Rescan Tab
                </button>
                <button style="flex:1; background: rgba(30,41,59,0.8); border:1px solid #475569; color:#F8FAFC; padding:10px; border-radius:8px; font-size:13px; font-weight:700; cursor:pointer;">
                  📊 Full Dashboard
                </button>
              </div>
            </div>

            <!-- Popup Footer -->
            <div style="background: #080D1A; padding: 10px 20px; font-size: 10px; color: #64748B; border-top: 1px solid #1E293B; text-align:center;">
              Manifest V3 • activeTab API • Connected: http://127.0.0.1:8000
            </div>
          </div>
        </div>

        <!-- Caption Bar -->
        <div class="caption-bar">
          <div class="caption-tag" style="background:${themeColor};">${captionTag}</div>
          <div class="caption-text">${captionText}</div>
        </div>

        ${renderCursorSvg(cursorX, cursorY)}
      </body>
      </html>
    `;

    await page.setContent(html, { waitUntil: 'domcontentloaded' });
    const buffer = await page.screenshot({ type: 'png' });
    ffmpeg.stdin.write(buffer);

    if (frame % 200 === 0) {
      console.log(`[Video 03] Rendered frame ${frame} / ${TOTAL_FRAMES} (${((frame / TOTAL_FRAMES) * 100).toFixed(1)}%)`);
    }
  }

  ffmpeg.stdin.end();
  await browser.close();

  await new Promise((resolve) => {
    ffmpeg.on('close', (code) => {
      console.log(`[+] Video 03 completed with exit code ${code}: ${outputPath}`);
      resolve();
    });
  });
}

generateVideo03().catch(console.error);

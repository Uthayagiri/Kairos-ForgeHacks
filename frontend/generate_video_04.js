import puppeteer from 'puppeteer';
import { spawn } from 'child_process';
import path from 'path';
import { fileURLToPath } from 'url';
import { FFMPEG_PATH, VIDEOS_DIR } from './video_helpers.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function generateVideo04() {
  const outputPath = path.join(VIDEOS_DIR, '04_extension_pre_navigation_warning.mp4');
  console.log(`[+] Starting generation of: ${outputPath}`);

  const FPS = 30;
  const DURATION_SEC = 45;
  const TOTAL_FRAMES = FPS * DURATION_SEC; // 1350 frames

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

  ffmpeg.stderr.on('data', (d) => {});

  const browser = await puppeteer.launch({
    headless: 'new',
    args: [
      '--no-sandbox',
      '--disable-setuid-sandbox',
      '--disable-dev-shm-usage',
      '--disable-gpu'
    ]
  });

  const page = await browser.newPage();
  await page.setViewport({ width: 1920, height: 1080 });

  const targetLure = 'http://paypal-security-update.account-verification.login.top/auth/verify';

  const baseHtml = `
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="utf-8">
      <style>
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
          background: rgba(239, 68, 68, 0.1);
          border: 1px solid rgba(239, 68, 68, 0.35);
          color: #EF4444;
        }
        .badge-dot {
          width: 8px;
          height: 8px;
          border-radius: 50%;
          background: #EF4444;
          box-shadow: 0 0 8px #EF4444;
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
          background: #EF4444;
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
        .stage-container {
          flex: 1;
          display: none;
          height: calc(1080px - 150px);
        }
      </style>
    </head>
    <body>
      <div class="navbar">
        <div class="logo">
          <span style="font-size: 26px;">🛡️</span>
          <span>PhishGuard <span style="color: #3B82F6;">AI</span></span>
        </div>
        <div style="display:flex; gap: 24px; font-size: 14px; font-weight: 500; color: #94A3B8;">
          <span>Live Scanner</span>
          <span>Comparative Forensics</span>
          <span>Dashboard</span>
          <span style="color: #EF4444; font-weight: 700;">Pre-Navigation Warning</span>
          <span>Extension</span>
        </div>
        <div class="badge-online">
          <span class="badge-dot"></span>
          <span>Navigation Guard Active (chrome.webNavigation)</span>
        </div>
      </div>

      <!-- Stage 1: Browsing / Email -->
      <div id="stage-browsing" class="stage-container" style="padding: 30px 60px;">
        <div style="background: #FFFFFF; color: #1E293B; border-radius: 12px; height: 100%; padding: 40px 60px; box-shadow: 0 20px 40px rgba(0,0,0,0.6);">
          <div style="font-size: 14px; color: #64748B; margin-bottom: 20px;">Inbox &gt; Message Details</div>
          <h2 style="font-size: 28px; font-weight: 800; color: #0F172A; margin-bottom: 20px;">⚠️ Urgent: Payment Account Verification Required</h2>
          <div style="background: #F8FAFC; border: 1px solid #E2E8F0; border-radius: 8px; padding: 24px; max-width: 800px;">
            <p style="font-size: 16px; color: #334155; line-height: 1.6; margin-bottom: 20px;">
              Dear Customer,<br><br>
              We detected unusual login activity on your payment account. To avoid temporary suspension, please verify your credentials immediately through our authentication portal:
            </p>
            <div style="margin: 20px 0;">
              <a href="#" style="background: #2563EB; color: #FFFFFF; text-decoration: none; padding: 12px 24px; border-radius: 6px; font-weight: 700; font-size: 15px; display: inline-block;">
                Verify Account Security Now &rarr;
              </a>
            </div>
            <div style="font-size: 12px; font-family: monospace; color: #64748B; margin-top: 14px;">
              Link destination: <span style="color: #DC2626;">${targetLure}</span>
            </div>
          </div>
        </div>
      </div>

      <!-- Stage 2: Intercepting -->
      <div id="stage-intercepting" class="stage-container" style="flex-direction:column; align-items:center; justify-content:center;">
        <div class="glass-card" style="padding: 40px 60px; text-align:center; max-width:700px;">
          <div style="font-size: 50px; margin-bottom: 20px;">🛡️</div>
          <h2 style="font-size: 28px; font-weight: 800; color: #F8FAFC; margin-bottom: 12px;">PhishGuard AI Interception Active</h2>
          <p style="font-size: 16px; color: #94A3B8; line-height: 1.6;">
            Evaluating destination risk before allowing navigation:<br>
            <span style="font-family:monospace; color:#EF4444; font-size:14px;">${targetLure}</span>
          </p>
        </div>
      </div>

      <!-- Stage 3: Security Interstitial Warning -->
      <div id="stage-warning" class="stage-container" style="flex-direction:column; align-items:center; justify-content:center; padding: 20px 40px;">
        <div class="glass-card" style="width: 100%; max-width: 1000px; padding: 40px 50px; border-color: rgba(239, 68, 68, 0.6); box-shadow: 0 0 50px rgba(239, 68, 68, 0.25);">
          <div style="display:flex; align-items:center; gap: 24px; margin-bottom: 30px;">
            <div style="width: 70px; height: 70px; border-radius: 16px; background: rgba(239, 68, 68, 0.2); border: 2px solid #EF4444; display:flex; align-items:center; justify-content:center; font-size: 36px;">
              ⚠️
            </div>
            <div>
              <h1 style="font-size: 32px; font-weight: 800; color: #EF4444; letter-spacing: -0.5px; margin-bottom: 6px;">
                CRITICAL PHISHING THREAT INTERCEPTED
              </h1>
              <p style="font-size: 16px; color: #94A3B8;">
                PhishGuard AI has blocked navigation to this destination to protect credentials and private data.
              </p>
            </div>
          </div>

          <div style="background: rgba(30, 41, 59, 0.7); border: 1px solid #334155; border-radius: 10px; padding: 14px 20px; display:flex; justify-content:space-between; align-items:center; margin-bottom: 28px;">
            <div>
              <div style="font-size: 11px; color: #94A3B8; font-weight:700; text-transform:uppercase; margin-bottom: 4px;">TARGET DESTINATION BLOCKED</div>
              <div style="font-family:monospace; font-size: 14px; color: #FCA5A5;">${targetLure}</div>
            </div>
            <div style="background: #EF4444; color:white; font-size:14px; font-weight:800; padding:8px 16px; border-radius:8px;">
              98.6% RISK SCORE
            </div>
          </div>

          <div style="background: rgba(15, 23, 42, 0.6); border: 1px solid #334155; border-radius: 10px; padding: 24px; margin-bottom: 32px;">
            <div style="font-size: 14px; font-weight: 700; color: #F8FAFC; margin-bottom: 16px;">Identified Threat Signals & Forensic Findings:</div>
            <div style="display:flex; flex-direction:column; gap: 12px; font-size: 14px;">
              <div style="display:flex; align-items:center; gap: 12px; color: #E2E8F0;">
                <span style="color: #EF4444; font-size: 18px;">🔴</span>
                <span><strong style="color:#EF4444;">High-Risk Abused TLD:</strong> Domain utilizes top-level domain (<code style="color:#FCA5A5;">.top</code>) heavily associated with malicious credential theft campaigns.</span>
              </div>
              <div style="display:flex; align-items:center; gap: 12px; color: #E2E8F0;">
                <span style="color: #EF4444; font-size: 18px;">🔴</span>
                <span><strong style="color:#EF4444;">Deceptive Authentication Lure:</strong> URL contains sensitive keywords (<code style="color:#FCA5A5;">paypal, security, verification, login</code>) designed to mimic legitimate financial portals.</span>
              </div>
              <div style="display:flex; align-items:center; gap: 12px; color: #E2E8F0;">
                <span style="color: #EF4444; font-size: 18px;">🔴</span>
                <span><strong style="color:#EF4444;">Unencrypted Transmission:</strong> Plain HTTP protocol lacks TLS cryptographic validation, exposing passwords and session tokens to interception.</span>
              </div>
            </div>
          </div>

          <div style="display:flex; gap: 20px; align-items:center;">
            <button id="btn-return-safety" style="flex:1.5; background: #EF4444; color:white; border:none; padding: 18px 28px; border-radius: 10px; font-size: 17px; font-weight: 800; cursor:pointer; display:flex; align-items:center; justify-content:center; gap: 10px; box-shadow: 0 10px 25px rgba(239,68,68,0.4);">
              <span>🛡️</span>
              <span>RETURN TO SAFETY (Recommended)</span>
            </button>
            <button style="flex:1; background: rgba(30, 41, 59, 0.8); border: 1px solid #475569; color:#F8FAFC; padding: 18px 24px; border-radius: 10px; font-size: 15px; font-weight: 700; cursor:pointer;">
              📊 View Threat Forensics
            </button>
          </div>

          <div style="display:flex; justify-content:space-between; margin-top: 20px; font-size: 12px; color: #64748B;">
            <span>PhishGuard AI Security Interstitial • Extension File: <code style="color:#94A3B8;">warning/warning.html</code></span>
            <span>Advanced Override: Available with Explicit Confirmation</span>
          </div>
        </div>
      </div>

      <!-- Stage 4: Returned to Safety -->
      <div id="stage-returned" class="stage-container" style="padding: 30px 60px;">
        <div style="background: #FFFFFF; color: #1E293B; border-radius: 12px; height: 100%; padding: 40px 60px; box-shadow: 0 20px 40px rgba(0,0,0,0.6); display:flex; flex-direction:column; align-items:center; justify-content:center; text-align:center;">
          <div style="width: 80px; height: 80px; border-radius: 50%; background: #DCFCE7; border: 2px solid #10B981; display:flex; align-items:center; justify-content:center; font-size: 40px; margin-bottom: 24px;">
            ✅
          </div>
          <h1 style="font-size: 36px; font-weight: 800; color: #065F46; margin-bottom: 12px;">Returned to Trusted Safe Browsing</h1>
          <p style="font-size: 18px; color: #475569; max-width: 600px; line-height: 1.6; margin-bottom: 30px;">
            The connection to the high-risk phishing destination was aborted. No passwords, session cookies, or personal data were transmitted.
          </p>
          <div style="background: #F1F5F9; border: 1px solid #CBD5E1; border-radius: 8px; padding: 12px 24px; font-family: monospace; font-size: 14px; color: #334155;">
            Current Active Origin: <span style="color: #2563EB;">https://mytrustedportal.com/inbox</span>
          </div>
        </div>
      </div>

      <!-- Caption Bar -->
      <div class="caption-bar">
        <div id="caption-tag" class="caption-tag">PRE-NAV INTERCEPTION</div>
        <div id="caption-text" class="caption-text">PhishGuard AI Pre-Navigation Interceptor</div>
      </div>

      <!-- Mouse Cursor -->
      <div id="mouse-cursor" class="cursor-pointer" style="left: 960px; top: 800px;">
        <svg width="24" height="24" viewBox="0 0 24 24" fill="none">
          <path d="M5.5 3.21V20.8c0 .45.54.67.85.35l4.86-4.86a.5.5 0 0 1 .35-.15h6.87c.45 0 .67-.54.35-.85L5.85 2.35c-.32-.32-.85-.1-.85.36z" fill="#EF4444" stroke="#FFFFFF" stroke-width="1.5"/>
        </svg>
      </div>

      <script>
        function easeInOutQuad(t) {
          return t < 0.5 ? 2 * t * t : -1 + (4 - 2 * t) * t;
        }

        window.renderFrame = function(tSec) {
          const sBrowsing = document.getElementById('stage-browsing');
          const sIntercepting = document.getElementById('stage-intercepting');
          const sWarning = document.getElementById('stage-warning');
          const sReturned = document.getElementById('stage-returned');
          const capTag = document.getElementById('caption-tag');
          const capText = document.getElementById('caption-text');
          const cursor = document.getElementById('mouse-cursor');
          const btnSafety = document.getElementById('btn-return-safety');

          sBrowsing.style.display = 'none';
          sIntercepting.style.display = 'none';
          sWarning.style.display = 'none';
          sReturned.style.display = 'none';

          let cursorX = 960;
          let cursorY = 800;
          let isClick = false;

          if (tSec < 12) {
            sBrowsing.style.display = 'block';
            capTag.textContent = 'DECEPTIVE LINK';
            capTag.style.background = '#EF4444';
            capText.textContent = 'User encounters an unverified link masquerading as a PayPal security verification.';
            const prog = tSec / 12;
            cursorX = 400 + (300) * easeInOutQuad(prog);
            cursorY = 500 + (-80) * easeInOutQuad(prog);
            if (tSec >= 11 && tSec < 11.5) isClick = true;
          } else if (tSec < 18) {
            sIntercepting.style.display = 'flex';
            capTag.textContent = 'PRE-NAV INTERCEPTION';
            capTag.style.background = '#EF4444';
            capText.textContent = 'Pre-navigation interceptor halts outbound connection before malicious scripts or assets can load.';
            cursorX = 960;
            cursorY = 540;
          } else if (tSec < 36) {
            sWarning.style.display = 'flex';
            capTag.textContent = 'SECURITY INTERSTITIAL';
            capTag.style.background = '#EF4444';
            capText.textContent = 'Local security interstitial (warning.html) displays 98.6% threat score and actionable safety options.';
            const prog = (tSec - 18) / 18;
            cursorX = 700 + (680 - 700) * Math.sin(prog * Math.PI);
            cursorY = 600 + (650 - 600) * easeInOutQuad(Math.min(1, prog * 1.5));
            if (tSec >= 34.5 && tSec < 35.0) {
              isClick = true;
              btnSafety.style.background = '#B91C1C';
              btnSafety.style.transform = 'scale(0.97)';
            } else {
              btnSafety.style.background = '#EF4444';
              btnSafety.style.transform = 'scale(1.0)';
            }
          } else {
            sReturned.style.display = 'block';
            capTag.textContent = 'SAFE RETURN';
            capTag.style.background = '#10B981';
            capText.textContent = 'User clicked Return to Safety: Browser navigates back to trusted origins with zero credential exposure.';
            cursorX = 960;
            cursorY = 500;
          }

          cursor.style.left = cursorX + 'px';
          cursor.style.top = cursorY + 'px';
          cursor.style.transform = isClick ? 'scale(0.85)' : 'scale(1.0)';
        };
      </script>
    </body>
    </html>
  `;

  await page.setContent(baseHtml, { waitUntil: 'domcontentloaded' });

  for (let frame = 0; frame < TOTAL_FRAMES; frame++) {
    const tSec = frame / FPS;
    await page.evaluate((t) => window.renderFrame(t), tSec);
    const buffer = await page.screenshot({ type: 'png' });
    ffmpeg.stdin.write(buffer);

    if (frame % 200 === 0) {
      console.log(`[Video 04] Rendered frame ${frame} / ${TOTAL_FRAMES} (${((frame / TOTAL_FRAMES) * 100).toFixed(1)}%)`);
    }
  }

  ffmpeg.stdin.end();
  await browser.close();

  await new Promise((resolve) => {
    ffmpeg.on('close', (code) => {
      console.log(`[+] Video 04 completed with exit code ${code}: ${outputPath}`);
      resolve();
    });
  });
}

generateVideo04().catch(console.error);

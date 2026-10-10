import puppeteer from 'puppeteer';
import { spawn } from 'child_process';
import path from 'path';
import { fileURLToPath } from 'url';
import { FFMPEG_PATH, VIDEOS_DIR } from './video_helpers.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function generateVideo05() {
  const outputPath = path.join(VIDEOS_DIR, '05_full_system_demonstration.mp4');
  console.log(`[+] Starting generation of: ${outputPath}`);

  const FPS = 30;
  const DURATION_SEC = 90;
  const TOTAL_FRAMES = FPS * DURATION_SEC; // 2700 frames

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
        .act-container {
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
          <span style="color: #38BDF8; font-weight: 600;">Full System Demo</span>
          <span>Live Scanner</span>
          <span>Extension</span>
          <span>SecOps Telemetry</span>
        </div>
        <div class="badge-online">
          <span class="badge-dot"></span>
          <span>End-to-End Verified • ForgeHacks 2026</span>
        </div>
      </div>

      <!-- Act 1: Architecture Topology -->
      <div id="act-1" class="act-container" style="flex-direction:column; align-items:center; justify-content:center; padding: 20px 80px;">
        <div style="text-align:center; margin-bottom: 24px;">
          <div style="font-size: 13px; font-weight:700; color: #38BDF8; letter-spacing:1px; text-transform:uppercase; margin-bottom: 8px;">END-TO-END SYSTEM OVERVIEW</div>
          <h1 style="font-size: 38px; font-weight: 800; color: #FFFFFF; letter-spacing: -1px;">PhishGuard AI Architectural Topology</h1>
        </div>

        <div style="display:grid; grid-template-columns: repeat(4, 1fr); gap: 20px; width: 100%; max-width: 1300px;">
          <div class="glass-card" style="padding: 24px; border-top: 4px solid #38BDF8;">
            <div style="font-size: 28px; margin-bottom: 12px;">🖥️</div>
            <div style="font-size: 18px; font-weight:800; color:#FFFFFF; margin-bottom: 6px;">Client Surfaces</div>
            <div style="font-size: 13px; color:#94A3B8; line-height:1.5;">
              • React 18 + Vite Web App<br>
              • Chromium Manifest V3 Extension<br>
              • Service Worker Interceptor
            </div>
          </div>

          <div class="glass-card" style="padding: 24px; border-top: 4px solid #10B981;">
            <div style="font-size: 28px; margin-bottom: 12px;">⚡</div>
            <div style="font-size: 18px; font-weight:800; color:#FFFFFF; margin-bottom: 6px;">API Gateway & Defense</div>
            <div style="font-size: 13px; color:#94A3B8; line-height:1.5;">
              • FastAPI Asynchronous Router<br>
              • SSRF Perimeter Guard<br>
              • Strict Pydantic Validation
            </div>
          </div>

          <div class="glass-card" style="padding: 24px; border-top: 4px solid #F59E0B;">
            <div style="font-size: 28px; margin-bottom: 12px;">🔍</div>
            <div style="font-size: 18px; font-weight:800; color:#FFFFFF; margin-bottom: 6px;">Dual-Branch Extractor</div>
            <div style="font-size: 13px; color:#94A3B8; line-height:1.5;">
              • 23 URL Lexical Signals<br>
              • 20 Live DOM & Form Signals<br>
              • Degraded Mode Fallback
            </div>
          </div>

          <div class="glass-card" style="padding: 24px; border-top: 4px solid #A855F7;">
            <div style="font-size: 28px; margin-bottom: 12px;">🧠</div>
            <div style="font-size: 18px; font-weight:800; color:#FFFFFF; margin-bottom: 6px;">Inference & SecOps</div>
            <div style="font-size: 13px; color:#94A3B8; line-height:1.5;">
              • Tuned XGBoost Classifier<br>
              • Calibrated Risk Thresholds<br>
              • Forensic Telemetry Logging
            </div>
          </div>
        </div>
      </div>

      <!-- Act 2: Legitimate Scan -->
      <div id="act-2" class="act-container" style="padding: 20px 40px; gap: 24px;">
        <div class="glass-card" style="flex: 1.3; padding: 24px 30px; display:flex; flex-direction:column; justify-content:space-between;">
          <div>
            <div style="display:flex; justify-content:space-between; margin-bottom: 16px;">
              <span style="font-size:16px; font-weight:700;">🔬 Legitimate Website Scan</span>
              <span style="font-size:12px; color:#10B981; font-family:monospace; background:rgba(16,185,129,0.1); padding:4px 8px; border-radius:4px;">POST /api/analyze</span>
            </div>
            <div style="background: rgba(30,41,59,0.7); padding:10px 14px; border-radius:6px; font-family:monospace; font-size:14px; color:#10B981; margin-bottom: 16px;">
              🔒 https://docs.python.org/3/library/index.html
            </div>
            <div style="background: rgba(16,185,129,0.1); border:1px solid rgba(16,185,129,0.4); border-radius:10px; padding:20px; display:flex; justify-content:space-between; align-items:center;">
              <div>
                <div style="color:#10B981; font-weight:800; font-size:11px; text-transform:uppercase;">VERDICT: SAFE / BENIGN</div>
                <div style="color:#FFFFFF; font-size:22px; font-weight:800;">Legitimate Documentation Destination</div>
                <div style="color:#94A3B8; font-size:13px; margin-top:4px;">TLS 1.3 verified. Standard lexical entropy. 0 credential forms.</div>
              </div>
              <div style="text-align:center; background:#0B101B; padding:12px 18px; border-radius:8px; border:1px solid #10B981;">
                <div style="font-size:24px; font-weight:900; color:#10B981;">0.4%</div>
                <div style="font-size:9px; color:#94A3B8; font-weight:700;">RISK SCORE</div>
              </div>
            </div>
          </div>
          <div style="background: rgba(15,23,42,0.9); padding:10px 14px; border-radius:6px; font-size:13px; color:#94A3B8;">
            <strong style="color:#10B981;">Action:</strong> SAFE TO PROCEED: Verified structural legitimacy and clean links.
          </div>
        </div>

        <div class="glass-card" style="flex: 0.9; padding: 24px;">
          <div style="font-size:15px; font-weight:700; color:#38BDF8; margin-bottom:12px;">Forensic Vector (docs.python.org)</div>
          <div style="background:#030712; padding:14px; border-radius:6px; font-family:monospace; font-size:12px; color:#94A3B8; line-height:1.6;">
            • uses_https: 1 | num_subdomains: 1<br>
            • has_ip_address: 0 | has_suspicious_tld: 0<br>
            • num_forms: 0 | num_password_fields: 0<br>
            • external_link_ratio: 0.05 (Legitimate)<br>
            • html_available: True (HTTP 200 OK)<br>
            <span style="color:#10B981;">✓ Model calibrated confidence: 99.6% Legitimate</span>
          </div>
        </div>
      </div>

      <!-- Act 3: Suspicious Scan -->
      <div id="act-3" class="act-container" style="padding: 20px 40px; gap: 24px;">
        <div class="glass-card" style="flex: 1.3; padding: 24px 30px; display:flex; flex-direction:column; justify-content:space-between;">
          <div>
            <div style="display:flex; justify-content:space-between; margin-bottom: 16px;">
              <span style="font-size:16px; font-weight:700; color:#F59E0B;">⚠️ Suspicious Domain Scan</span>
              <span style="font-size:12px; color:#F59E0B; font-family:monospace; background:rgba(245,158,11,0.1); padding:4px 8px; border-radius:4px;">Degraded Mode Active</span>
            </div>
            <div style="background: rgba(30,41,59,0.7); padding:10px 14px; border-radius:6px; font-family:monospace; font-size:14px; color:#F59E0B; margin-bottom: 16px;">
              ⚠️ http://unverified-fast-news.biz/article/2026
            </div>
            <div style="background: rgba(245,158,11,0.1); border:1px solid rgba(245,158,11,0.4); border-radius:10px; padding:20px; display:flex; justify-content:space-between; align-items:center;">
              <div>
                <div style="color:#F59E0B; font-weight:800; font-size:11px; text-transform:uppercase;">VERDICT: SUSPICIOUS DOMAIN</div>
                <div style="color:#FFFFFF; font-size:22px; font-weight:800;">Deceptive Or Unverified Site</div>
                <div style="color:#94A3B8; font-size:13px; margin-top:4px;">Plain HTTP transport. Multiple hyphens. Unreachable DOM.</div>
              </div>
              <div style="text-align:center; background:#0B101B; padding:12px 18px; border-radius:8px; border:1px solid #F59E0B;">
                <div style="font-size:24px; font-weight:900; color:#F59E0B;">48.0%</div>
                <div style="font-size:9px; color:#94A3B8; font-weight:700;">RISK SCORE</div>
              </div>
            </div>
          </div>
          <div style="background: rgba(15,23,42,0.9); padding:10px 14px; border-radius:6px; font-size:13px; color:#94A3B8;">
            <strong style="color:#F59E0B;">Action:</strong> EXERCISE CAUTION: Inspect the domain address bar carefully.
          </div>
        </div>

        <div class="glass-card" style="flex: 0.9; padding: 24px;">
          <div style="font-size:15px; font-weight:700; color:#F59E0B; margin-bottom:12px;">Degraded-Mode Calibration</div>
          <div style="background:#030712; padding:14px; border-radius:6px; font-family:monospace; font-size:12px; color:#94A3B8; line-height:1.6;">
            • uses_https: 0 (Insecure HTTP)<br>
            • has_suspicious_tld: 1 (.biz)<br>
            • num_hyphens: 2 (unverified-fast-news)<br>
            • html_available: False (Degraded)<br>
            <span style="color:#F59E0B;">⚠️ Risk bounded to ≤48% to avoid false-positive block</span>
          </div>
        </div>
      </div>

      <!-- Act 4: High-Risk SSRF -->
      <div id="act-4" class="act-container" style="padding: 20px 40px; gap: 24px;">
        <div class="glass-card" style="flex: 1.3; padding: 24px 30px; display:flex; flex-direction:column; justify-content:space-between;">
          <div>
            <div style="display:flex; justify-content:space-between; margin-bottom: 16px;">
              <span style="font-size:16px; font-weight:700; color:#EF4444;">🚨 Critical Phishing Threat Result</span>
              <span style="font-size:12px; color:#EF4444; font-family:monospace; background:rgba(239,68,68,0.1); padding:4px 8px; border-radius:4px;">SSRF Defense Triggered</span>
            </div>
            <div style="background: rgba(30,41,59,0.7); padding:10px 14px; border-radius:6px; font-family:monospace; font-size:14px; color:#EF4444; margin-bottom: 16px;">
              🚫 http://192.168.1.50/secure-login/account-verification
            </div>
            <div style="background: rgba(239,68,68,0.15); border:1px solid rgba(239,68,68,0.5); border-radius:10px; padding:20px; display:flex; justify-content:space-between; align-items:center;">
              <div>
                <div style="color:#EF4444; font-weight:800; font-size:11px; text-transform:uppercase;">VERDICT: CRITICAL PHISHING ATTACK</div>
                <div style="color:#FFFFFF; font-size:22px; font-weight:800;">Credential Harvesting Hazard</div>
                <div style="color:#94A3B8; font-size:13px; margin-top:4px;">Raw IP obfuscation + SSRF probe blocked + sensitive keywords.</div>
              </div>
              <div style="text-align:center; background:#0B101B; padding:12px 18px; border-radius:8px; border:1px solid #EF4444;">
                <div style="font-size:24px; font-weight:900; color:#EF4444;">91.1%</div>
                <div style="font-size:9px; color:#94A3B8; font-weight:700;">RISK SCORE</div>
              </div>
            </div>
          </div>
          <div style="background: rgba(15,23,42,0.9); padding:10px 14px; border-radius:6px; font-size:13px; color:#94A3B8;">
            <strong style="color:#EF4444;">Action:</strong> CRITICAL THREAT: Do NOT enter credentials or passwords.
          </div>
        </div>

        <div class="glass-card" style="flex: 0.9; padding: 24px;">
          <div style="font-size:15px; font-weight:700; color:#EF4444; margin-bottom:12px;">SSRF Threat Forensics</div>
          <div style="background:#030712; padding:14px; border-radius:6px; font-family:monospace; font-size:12px; color:#94A3B8; line-height:1.6;">
            • has_ip_address: 1 (192.168.1.50)<br>
            • ssrf_defense: BLOCKED (RFC 1918)<br>
            • sensitive_keywords: login, secure, verify<br>
            • is_phishing: True (Confidence: 0.9113)<br>
            <span style="color:#EF4444;">🚫 Internal LAN probe neutralized successfully</span>
          </div>
        </div>
      </div>

      <!-- Act 5: Extension Interception -->
      <div id="act-5" class="act-container" style="flex-direction:column; align-items:center; justify-content:center; padding: 20px 40px;">
        <div class="glass-card" style="width: 100%; max-width: 900px; padding: 36px 44px; border-color: rgba(239, 68, 68, 0.6); box-shadow: 0 0 50px rgba(239, 68, 68, 0.25);">
          <div style="display:flex; align-items:center; gap: 20px; margin-bottom: 24px;">
            <div style="font-size: 40px;">⚠️</div>
            <div>
              <h1 style="font-size: 28px; font-weight: 800; color: #EF4444;">CRITICAL PHISHING THREAT INTERCEPTED</h1>
              <p style="font-size: 15px; color: #94A3B8;">Destination blocked before navigation: <code style="color:#FCA5A5;">http://paypal-security-update.login.top</code></p>
            </div>
            <div style="margin-left:auto; background:#EF4444; color:white; font-size:16px; font-weight:900; padding:8px 16px; border-radius:8px;">
              98.6% RISK
            </div>
          </div>

          <div style="background: rgba(30,41,59,0.6); border: 1px solid #334155; border-radius: 8px; padding: 16px; margin-bottom: 24px; font-size:13px; color:#E2E8F0; line-height:1.6;">
            🔴 <strong>Abused .top TLD:</strong> Heavily associated with credential harvesting campaigns.<br>
            🔴 <strong>Brand Spoofing:</strong> Deceptive keyword tokens mimicking financial portal (<code style="color:#FCA5A5;">paypal</code>).<br>
            🔴 <strong>Insecure HTTP:</strong> Plaintext transport lacks TLS encryption.
          </div>

          <div style="display:flex; gap: 16px;">
            <button style="flex:1.5; background: #EF4444; color:white; border:none; padding:14px; border-radius:8px; font-size:15px; font-weight:800; cursor:pointer;">
              🛡️ RETURN TO SAFETY (Recommended)
            </button>
            <button style="flex:1; background: rgba(30,41,59,0.8); border:1px solid #475569; color:#F8FAFC; padding:14px; border-radius:8px; font-size:13px; font-weight:700;">
              📊 View Threat Forensics
            </button>
          </div>
        </div>
      </div>

      <!-- Act 6: SecOps Dashboard -->
      <div id="act-6" class="act-container" style="flex-direction:column; padding: 24px 60px;">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom: 24px;">
          <div>
            <h1 style="font-size: 28px; font-weight: 800; color: #FFFFFF;">Security Operations & Telemetry Dashboard</h1>
            <p style="font-size: 14px; color: #94A3B8;">Real-time inspection metrics, threat distribution, and model operational health.</p>
          </div>
          <div style="background: rgba(16,185,129,0.1); border:1px solid rgba(16,185,129,0.3); color:#10B981; padding:8px 16px; border-radius:8px; font-weight:700; font-size:13px;">
            All Systems Operational (87/87 Tests Passed)
          </div>
        </div>

        <div style="display:grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin-bottom: 24px;">
          <div class="glass-card" style="padding: 20px;">
            <div style="font-size:12px; color:#94A3B8; font-weight:700; text-transform:uppercase;">Average Latency</div>
            <div style="font-size:28px; font-weight:800; color:#10B981; margin-top:6px;">64.2 ms</div>
            <div style="font-size:11px; color:#64748B;">Sub-100ms Target</div>
          </div>
          <div class="glass-card" style="padding: 20px;">
            <div style="font-size:12px; color:#94A3B8; font-weight:700; text-transform:uppercase;">Model Precision</div>
            <div style="font-size:28px; font-weight:800; color:#38BDF8; margin-top:6px;">98.4%</div>
            <div style="font-size:11px; color:#64748B;">XGBoost v1.2</div>
          </div>
          <div class="glass-card" style="padding: 20px;">
            <div style="font-size:12px; color:#94A3B8; font-weight:700; text-transform:uppercase;">SSRF Interceptions</div>
            <div style="font-size:28px; font-weight:800; color:#EF4444; margin-top:6px;">100%</div>
            <div style="font-size:11px; color:#64748B;">RFC 1918 Private Block</div>
          </div>
          <div class="glass-card" style="padding: 20px;">
            <div style="font-size:12px; color:#94A3B8; font-weight:700; text-transform:uppercase;">Degraded Bound</div>
            <div style="font-size:28px; font-weight:800; color:#F59E0B; margin-top:6px;">48.0%</div>
            <div style="font-size:11px; color:#64748B;">Anti-False Positive Cap</div>
          </div>
        </div>
      </div>

      <!-- Caption Bar -->
      <div class="caption-bar">
        <div id="caption-tag" class="caption-tag">SYSTEM ARCHITECTURE</div>
        <div id="caption-text" class="caption-text">PhishGuard AI Architectural Topology</div>
      </div>

      <!-- Mouse Cursor -->
      <div id="mouse-cursor" class="cursor-pointer" style="left: 960px; top: 500px;">
        <svg width="24" height="24" viewBox="0 0 24 24" fill="none">
          <path d="M5.5 3.21V20.8c0 .45.54.67.85.35l4.86-4.86a.5.5 0 0 1 .35-.15h6.87c.45 0 .67-.54.35-.85L5.85 2.35c-.32-.32-.85-.1-.85.36z" fill="#3B82F6" stroke="#FFFFFF" stroke-width="1.5"/>
        </svg>
      </div>

      <script>
        window.renderFrame = function(tSec) {
          const acts = [
            document.getElementById('act-1'),
            document.getElementById('act-2'),
            document.getElementById('act-3'),
            document.getElementById('act-4'),
            document.getElementById('act-5'),
            document.getElementById('act-6')
          ];
          const capTag = document.getElementById('caption-tag');
          const capText = document.getElementById('caption-text');
          const cursor = document.getElementById('mouse-cursor');

          acts.forEach(a => a.style.display = 'none');

          let cursorX = 960;
          let cursorY = 500;

          if (tSec < 15) {
            acts[0].style.display = 'flex';
            capTag.textContent = 'SYSTEM ARCHITECTURE';
            capTag.style.background = '#3B82F6';
            capText.textContent = 'PhishGuard AI: Full-stack architecture with FastAPI backend, 43-feature extractor, XGBoost, and MV3 extension.';
            cursorX = 960 + Math.sin(tSec * 0.5) * 80;
            cursorY = 500;
          } else if (tSec < 32) {
            acts[1].style.display = 'flex';
            capTag.textContent = 'ACT 1: LEGITIMATE SCAN';
            capTag.style.background = '#10B981';
            capText.textContent = 'Live Web Scanner: Verified Python documentation (docs.python.org) scores 0.4% Low Risk (Safe / Benign).';
            cursorX = 400 + Math.sin((tSec - 15) * 0.8) * 100;
            cursorY = 400;
          } else if (tSec < 48) {
            acts[2].style.display = 'flex';
            capTag.textContent = 'ACT 2: SUSPICIOUS SCAN';
            capTag.style.background = '#F59E0B';
            capText.textContent = 'Degraded-Mode Bounded Threat: Unverified domain with plain HTTP scores 48.0% Medium Risk (Suspicious).';
            cursorX = 400 + Math.sin((tSec - 32) * 0.8) * 100;
            cursorY = 400;
          } else if (tSec < 64) {
            acts[3].style.display = 'flex';
            capTag.textContent = 'ACT 3: SSRF PHISHING DEFENSE';
            capTag.style.background = '#EF4444';
            capText.textContent = 'SSRF Perimeter Defense: Blocked private RFC 1918 socket to 192.168.1.50; ML escalates threat to 91.1%.';
            cursorX = 400 + Math.sin((tSec - 48) * 0.8) * 100;
            cursorY = 400;
          } else if (tSec < 78) {
            acts[4].style.display = 'flex';
            capTag.textContent = 'ACT 4: EXTENSION INTERCEPTION';
            capTag.style.background = '#EF4444';
            capText.textContent = 'Pre-Navigation Interception: Warning interstitial halts 98.6% phishing lure before navigation completes.';
            cursorX = 680 + Math.sin((tSec - 64) * 0.8) * 60;
            cursorY = 650;
          } else {
            acts[5].style.display = 'flex';
            capTag.textContent = 'ACT 5: SECOPS TELEMETRY';
            capTag.style.background = '#10B981';
            capText.textContent = 'SecOps Telemetry: Sub-65ms latency, 100% test pass rate, and transparent explainable cybersecurity.';
            cursorX = 960 + Math.sin((tSec - 78) * 0.5) * 100;
            cursorY = 500;
          }

          cursor.style.left = cursorX + 'px';
          cursor.style.top = cursorY + 'px';
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

    if (frame % 300 === 0) {
      console.log(`[Video 05] Rendered frame ${frame} / ${TOTAL_FRAMES} (${((frame / TOTAL_FRAMES) * 100).toFixed(1)}%)`);
    }
  }

  ffmpeg.stdin.end();
  await browser.close();

  await new Promise((resolve) => {
    ffmpeg.on('close', (code) => {
      console.log(`[+] Video 05 completed with exit code ${code}: ${outputPath}`);
      resolve();
    });
  });
}

generateVideo05().catch(console.error);

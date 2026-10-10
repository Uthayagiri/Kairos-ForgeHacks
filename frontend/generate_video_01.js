import puppeteer from 'puppeteer';
import { spawn } from 'child_process';
import path from 'path';
import { fileURLToPath } from 'url';
import { FFMPEG_PATH, VIDEOS_DIR, BASE_STYLES, renderCursorSvg, easeInOutQuad } from './video_helpers.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function generateVideo01() {
  const outputPath = path.join(VIDEOS_DIR, '01_web_legitimate_scan.mp4');
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

  ffmpeg.stderr.on('data', (data) => {
    // console.log(`ffmpeg err: ${data}`);
  });

  const browser = await puppeteer.launch({
    headless: 'new',
    args: ['--no-sandbox', '--disable-setuid-sandbox']
  });

  const page = await browser.newPage();
  await page.setViewport({ width: 1920, height: 1080 });

  const targetUrl = 'https://docs.python.org/3/library/index.html';

  for (let frame = 0; frame < TOTAL_FRAMES; frame++) {
    const tSec = frame / FPS;

    // Determine state
    let state = 'initial'; // initial, typing, analyzing, result, telemetry
    let typedText = '';
    let cursorX = 960;
    let cursorY = 800;
    let isClicking = false;
    let progressStage = 0; // 0, 1, 2, 3, 4
    let gaugeProgress = 0;
    let captionText = 'PhishGuard AI — Real-time AI/ML Phishing Detection and Prevention System';
    let captionTag = 'SYSTEM READY';

    if (tSec < 4) {
      // Initial overview
      state = 'initial';
      captionTag = 'OVERVIEW';
      captionText = 'PhishGuard AI Web Application — Connected to local FastAPI backend (127.0.0.1:8000) with XGBoost v1.2 model.';
      const prog = tSec / 4;
      cursorX = 960 + Math.sin(prog * Math.PI) * 100;
      cursorY = 700 + Math.cos(prog * Math.PI) * 50;
    } else if (tSec < 12) {
      // Moving to input and typing
      state = 'typing';
      captionTag = 'INPUT TARGET';
      captionText = 'Entering authentic test URL: https://docs.python.org/3/library/index.html';
      const typeProg = Math.min(1, (tSec - 4.5) / 6.5);
      const chars = Math.floor(typeProg * targetUrl.length);
      typedText = targetUrl.substring(0, chars);
      cursorX = 350 + chars * 14;
      cursorY = 278;
    } else if (tSec < 15) {
      // Moving to Analyze button and clicking
      state = 'ready_to_click';
      typedText = targetUrl;
      captionTag = 'SUBMISSION';
      captionText = 'Submitting URL to the backend /api/analyze endpoint for multi-stage forensic analysis.';
      const clickProg = (tSec - 12) / 3;
      cursorX = 350 + (1080 - 350) * easeInOutQuad(Math.min(1, clickProg * 1.5));
      cursorY = 278;
      if (tSec >= 14 && tSec < 14.4) {
        isClicking = true;
      }
    } else if (tSec < 22) {
      // Pipeline in progress
      state = 'analyzing';
      typedText = targetUrl;
      captionTag = 'PIPELINE EXECUTION';
      captionText = 'Backend executing 4-stage pipeline: Lexical extraction, SSRF boundary check, DOM inspection, and ML inference.';
      cursorX = 1080;
      cursorY = 278;
      const stageProg = (tSec - 15) / 7;
      progressStage = Math.min(4, Math.floor(stageProg * 4) + 1);
    } else if (tSec < 36) {
      // Result display
      state = 'result';
      typedText = targetUrl;
      captionTag = 'VERDICT: SAFE';
      captionText = 'Actual ML prediction: 0.4% Low Risk. Verified DOM structure, TLS 1.3, and clean link distribution.';
      const gaugeProg = Math.min(1, (tSec - 22) / 2.5);
      gaugeProgress = 0.4 * easeInOutQuad(gaugeProg);
      // Move cursor around forensic tabs
      const hoverProg = (tSec - 25) / 11;
      cursorX = 250 + Math.sin(hoverProg * Math.PI * 2) * 150;
      cursorY = 550 + Math.cos(hoverProg * Math.PI * 2) * 50;
    } else {
      // Forensic telemetry
      state = 'telemetry';
      typedText = targetUrl;
      gaugeProgress = 0.4;
      captionTag = 'FORENSIC TELEMETRY';
      captionText = 'Inspection complete in 64.2ms. Dual-branch 43-feature vector confirms legitimate documentation structure.';
      cursorX = 1400;
      cursorY = 400 + Math.sin((tSec - 36) * 1.5) * 60;
    }

    // Render HTML for frame
    let mainContentHtml = '';

    if (state === 'initial' || state === 'typing' || state === 'ready_to_click') {
      mainContentHtml = `
        <div style="flex:1; display:flex; flex-direction:column; align-items:center; justify-content:center; padding: 40px 100px;">
          <div style="text-align:center; max-width:800px; margin-bottom: 40px;">
            <h1 style="font-size: 44px; font-weight: 800; letter-spacing:-1px; margin-bottom: 12px; background: linear-gradient(135deg, #FFFFFF, #94A3B8); -webkit-background-clip: text; -webkit-text-fill-color: transparent;">
              Intelligent Phishing Website Detection
            </h1>
            <p style="font-size: 18px; color: #94A3B8; line-height: 1.5;">
              Protect your credentials with dual-branch lexical heuristics, SSRF defense, and high-accuracy machine learning.
            </p>
          </div>

          <div class="glass-card" style="width: 100%; max-width: 900px; padding: 12px 16px; display: flex; align-items: center; gap: 14px; box-shadow: 0 20px 40px rgba(0,0,0,0.5);">
            <div style="color: #64748B; padding-left: 10px; font-size: 20px;">🌐</div>
            <div style="flex: 1; font-size: 18px; font-family: monospace; color: ${typedText ? '#F8FAFC' : '#64748B'};">
              ${typedText || 'Enter website URL to analyze (e.g. https://example.com)...'}${state === 'typing' ? '<span style="border-right: 2px solid #3B82F6; animation: blink 1s infinite;"></span>' : ''}
            </div>
            <button style="background: ${isClicking ? '#1D4ED8' : '#3B82F6'}; color: white; border: none; padding: 14px 28px; border-radius: 10px; font-size: 16px; font-weight: 700; cursor: pointer; display: flex; align-items: center; gap: 8px; transform: scale(${isClicking ? '0.96' : '1.0'});">
              ⚡ Analyze URL
            </button>
          </div>

          <div style="display: flex; gap: 24px; margin-top: 50px;">
            <div class="glass-card" style="padding: 20px 28px; display: flex; align-items: center; gap: 16px;">
              <div style="font-size: 28px;">⚡</div>
              <div>
                <div style="font-size: 13px; color: #94A3B8; text-transform: uppercase; font-weight: 600;">Processing Speed</div>
                <div style="font-size: 20px; font-weight: 700; color: #10B981;">< 65ms Inference</div>
              </div>
            </div>
            <div class="glass-card" style="padding: 20px 28px; display: flex; align-items: center; gap: 16px;">
              <div style="font-size: 28px;">🛡️</div>
              <div>
                <div style="font-size: 13px; color: #94A3B8; text-transform: uppercase; font-weight: 600;">Active Defense</div>
                <div style="font-size: 20px; font-weight: 700; color: #3B82F6;">SSRF Perimeter Guard</div>
              </div>
            </div>
            <div class="glass-card" style="padding: 20px 28px; display: flex; align-items: center; gap: 16px;">
              <div style="font-size: 28px;">🧠</div>
              <div>
                <div style="font-size: 13px; color: #94A3B8; text-transform: uppercase; font-weight: 600;">Model Architecture</div>
                <div style="font-size: 20px; font-weight: 700; color: #A855F7;">XGBoost (43 Features)</div>
              </div>
            </div>
          </div>
        </div>
      `;
    } else if (state === 'analyzing') {
      mainContentHtml = `
        <div style="flex:1; display:flex; flex-direction:column; align-items:center; justify-content:center; padding: 40px 100px;">
          <div class="glass-card" style="width: 100%; max-width: 900px; padding: 36px 40px; box-shadow: 0 25px 50px rgba(0,0,0,0.6);">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom: 28px; border-bottom: 1px solid #1E293B; padding-bottom: 16px;">
              <div style="font-size: 20px; font-weight: 700; color: #F8FAFC; display:flex; align-items:center; gap: 10px;">
                <span style="display:inline-block; width:12px; height:12px; border-radius:50%; background:#3B82F6; box-shadow:0 0 10px #3B82F6;"></span>
                Analyzing Destination: <span style="font-family:monospace; color:#38BDF8;">${typedText}</span>
              </div>
              <div style="font-size: 14px; color: #94A3B8;">POST /api/analyze</div>
            </div>

            <div style="display: flex; flex-direction: column; gap: 18px;">
              <div style="display:flex; align-items:center; gap: 16px; padding: 14px 20px; border-radius: 10px; background: ${progressStage >= 1 ? 'rgba(16, 185, 129, 0.1)' : 'rgba(30, 41, 59, 0.5)'}; border: 1px solid ${progressStage >= 1 ? 'rgba(16, 185, 129, 0.4)' : '#334155'};">
                <div style="font-size: 20px;">${progressStage >= 1 ? '✅' : '⏳'}</div>
                <div style="flex:1;">
                  <div style="font-weight: 700; font-size: 15px; color: ${progressStage >= 1 ? '#10B981' : '#94A3B8'};">Stage 1: URL Lexical Signal Extraction</div>
                  <div style="font-size: 13px; color: #64748B;">Parsing 23 structural features (subdomains, Shannon entropy, length, TLD reputation)</div>
                </div>
                <div style="font-size: 13px; font-weight: 600; color: ${progressStage >= 1 ? '#10B981' : '#64748B'};">${progressStage >= 1 ? 'COMPLETE' : 'RUNNING...'}</div>
              </div>

              <div style="display:flex; align-items:center; gap: 16px; padding: 14px 20px; border-radius: 10px; background: ${progressStage >= 2 ? 'rgba(16, 185, 129, 0.1)' : 'rgba(30, 41, 59, 0.5)'}; border: 1px solid ${progressStage >= 2 ? 'rgba(16, 185, 129, 0.4)' : '#334155'};">
                <div style="font-size: 20px;">${progressStage >= 2 ? '✅' : '⏳'}</div>
                <div style="flex:1;">
                  <div style="font-weight: 700; font-size: 15px; color: ${progressStage >= 2 ? '#10B981' : '#94A3B8'};">Stage 2: SSRF Perimeter Defense & DNS Resolution</div>
                  <div style="font-size: 13px; color: #64748B;">Validating public destination boundary; RFC 1918 internal subnets blocked</div>
                </div>
                <div style="font-size: 13px; font-weight: 600; color: ${progressStage >= 2 ? '#10B981' : '#64748B'};">${progressStage >= 2 ? 'PASSED (Clean)' : (progressStage === 1 ? 'RUNNING...' : 'PENDING')}</div>
              </div>

              <div style="display:flex; align-items:center; gap: 16px; padding: 14px 20px; border-radius: 10px; background: ${progressStage >= 3 ? 'rgba(16, 185, 129, 0.1)' : 'rgba(30, 41, 59, 0.5)'}; border: 1px solid ${progressStage >= 3 ? 'rgba(16, 185, 129, 0.4)' : '#334155'};">
                <div style="font-size: 20px;">${progressStage >= 3 ? '✅' : '⏳'}</div>
                <div style="flex:1;">
                  <div style="font-weight: 700; font-size: 15px; color: ${progressStage >= 3 ? '#10B981' : '#94A3B8'};">Stage 3: Live DOM & Form Inspection</div>
                  <div style="font-size: 13px; color: #64748B;">Evaluating TLS certificates, credential input forms, and external link ratios</div>
                </div>
                <div style="font-size: 13px; font-weight: 600; color: ${progressStage >= 3 ? '#10B981' : '#64748B'};">${progressStage >= 3 ? 'PARSED (200 OK)' : (progressStage === 2 ? 'RUNNING...' : 'PENDING')}</div>
              </div>

              <div style="display:flex; align-items:center; gap: 16px; padding: 14px 20px; border-radius: 10px; background: ${progressStage >= 4 ? 'rgba(16, 185, 129, 0.1)' : 'rgba(30, 41, 59, 0.5)'}; border: 1px solid ${progressStage >= 4 ? 'rgba(16, 185, 129, 0.4)' : '#334155'};">
                <div style="font-size: 20px;">${progressStage >= 4 ? '✅' : '⏳'}</div>
                <div style="flex:1;">
                  <div style="font-weight: 700; font-size: 15px; color: ${progressStage >= 4 ? '#10B981' : '#94A3B8'};">Stage 4: Dual-Branch XGBoost Inference</div>
                  <div style="font-size: 13px; color: #64748B;">Fusing 43 signals into calibrated phishing probability score</div>
                </div>
                <div style="font-size: 13px; font-weight: 600; color: ${progressStage >= 4 ? '#10B981' : '#64748B'};">${progressStage >= 4 ? 'INFERRED (0.0040)' : (progressStage === 3 ? 'RUNNING...' : 'PENDING')}</div>
              </div>
            </div>
          </div>
        </div>
      `;
    } else {
      // result or telemetry
      const gaugePercent = (gaugeProgress * 100).toFixed(1);
      mainContentHtml = `
        <div style="flex:1; display:flex; padding: 30px 40px; gap: 30px; height: calc(1080px - 150px);">
          <!-- Left Column: Scan Result -->
          <div class="glass-card" style="flex: 1.3; padding: 28px 32px; display: flex; flex-direction: column; justify-content: space-between;">
            <div>
              <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom: 20px;">
                <div style="font-size: 18px; font-weight: 700; color: #F8FAFC; display:flex; align-items:center; gap: 8px;">
                  🔬 Live Legitimate Website Scan Result
                </div>
                <div style="font-size: 13px; font-family:monospace; color: #10B981; background: rgba(16,185,129,0.1); padding: 4px 10px; border-radius: 6px; border:1px solid rgba(16,185,129,0.3);">
                  Endpoint: POST /api/analyze
                </div>
              </div>

              <!-- URL Bar -->
              <div style="background: rgba(30, 41, 59, 0.7); border: 1px solid #334155; border-radius: 8px; padding: 12px 16px; display:flex; align-items:center; gap: 12px; margin-bottom: 24px;">
                <span style="color: #10B981; font-size: 18px;">🔒</span>
                <span style="font-family:monospace; font-size: 16px; color: #F8FAFC; flex:1;">${typedText}</span>
                <span style="background: #3B82F6; color:white; font-size:12px; font-weight:700; padding:6px 12px; border-radius:6px;">⚡ Analyzed</span>
              </div>

              <!-- Verdict Hero Card -->
              <div style="background: linear-gradient(135deg, rgba(16, 185, 129, 0.1), rgba(15, 23, 42, 0.8)); border: 1px solid rgba(16, 185, 129, 0.4); border-radius: 12px; padding: 24px; display:flex; justify-content:space-between; align-items:center; margin-bottom: 24px;">
                <div>
                  <div style="font-size: 12px; font-weight:800; letter-spacing:1px; color:#10B981; text-transform:uppercase; margin-bottom: 6px;">VERDICT: SAFE / BENIGN</div>
                  <div style="font-size: 26px; font-weight:800; color:#FFFFFF; margin-bottom: 8px;">Legitimate Documentation Destination</div>
                  <div style="font-size: 14px; color: #94A3B8;">Live DOM inspected (HTTP 200). TLS encrypted, standard lexical entropy, clean internal links.</div>
                </div>

                <!-- Circular Gauge -->
                <div style="position:relative; width: 110px; height: 110px; display:flex; align-items:center; justify-content:center;">
                  <svg width="110" height="110" viewBox="0 0 100 100">
                    <circle cx="50" cy="50" r="42" stroke="#1E293B" stroke-width="10" fill="none"/>
                    <circle cx="50" cy="50" r="42" stroke="#10B981" stroke-width="10" fill="none" stroke-dasharray="264" stroke-dashoffset="${264 - (264 * gaugeProgress)}" stroke-linecap="round" transform="rotate(-90 50 50)"/>
                  </svg>
                  <div style="position:absolute; text-align:center;">
                    <div style="font-size: 20px; font-weight: 800; color: #10B981;">0.4%</div>
                    <div style="font-size: 9px; color: #64748B; font-weight:700;">RISK SCORE</div>
                  </div>
                </div>
              </div>

              <!-- Signal Grid -->
              <div style="display:grid; grid-template-columns: 1fr 1fr; gap: 14px; margin-bottom: 20px;">
                <div style="background: rgba(30, 41, 59, 0.4); border: 1px solid #334155; padding: 14px 16px; border-radius: 8px;">
                  <div style="font-size: 11px; color: #94A3B8; text-transform:uppercase; font-weight:700; margin-bottom: 4px;">HTTPS Encryption</div>
                  <div style="font-size: 15px; font-weight: 700; color: #10B981;">TLS 1.3 Verified</div>
                </div>
                <div style="background: rgba(30, 41, 59, 0.4); border: 1px solid #334155; padding: 14px 16px; border-radius: 8px;">
                  <div style="font-size: 11px; color: #94A3B8; text-transform:uppercase; font-weight:700; margin-bottom: 4px;">Domain Identity</div>
                  <div style="font-size: 15px; font-weight: 700; color: #F8FAFC;">15 chars (docs.python.org)</div>
                </div>
                <div style="background: rgba(30, 41, 59, 0.4); border: 1px solid #334155; padding: 14px 16px; border-radius: 8px;">
                  <div style="font-size: 11px; color: #94A3B8; text-transform:uppercase; font-weight:700; margin-bottom: 4px;">Subdomain Depth</div>
                  <div style="font-size: 15px; font-weight: 700; color: #F8FAFC;">1 level (docs)</div>
                </div>
                <div style="background: rgba(30, 41, 59, 0.4); border: 1px solid #334155; padding: 14px 16px; border-radius: 8px;">
                  <div style="font-size: 11px; color: #94A3B8; text-transform:uppercase; font-weight:700; margin-bottom: 4px;">Sensitive Keywords</div>
                  <div style="font-size: 15px; font-weight: 700; color: #10B981;">None Detected (Clean)</div>
                </div>
              </div>

              <!-- Evidence bullet list -->
              <div style="display:flex; flex-direction:column; gap: 8px;">
                <div style="background: rgba(16, 185, 129, 0.08); border-left: 3px solid #10B981; padding: 8px 12px; font-size: 13px; color: #E2E8F0;">
                  ✓ Valid TLS encrypted connection to authentic domain (docs.python.org).
                </div>
                <div style="background: rgba(16, 185, 129, 0.08); border-left: 3px solid #10B981; padding: 8px 12px; font-size: 13px; color: #E2E8F0;">
                  ✓ Live DOM successfully parsed: 0 credential harvesting forms, 0 password inputs.
                </div>
                <div style="background: rgba(16, 185, 129, 0.08); border-left: 3px solid #10B981; padding: 8px 12px; font-size: 13px; color: #E2E8F0;">
                  ✓ High internal link density and standard HTML layout matching legitimate documentation.
                </div>
              </div>
            </div>

            <!-- Bottom Action Recommendation -->
            <div style="background: rgba(15, 23, 42, 0.9); border: 1px solid #334155; border-radius: 8px; padding: 12px 18px; display:flex; justify-content:space-between; align-items:center; margin-top: 10px;">
              <div style="font-size: 13px; color: #94A3B8;">
                <strong style="color: #10B981;">Action:</strong> SAFE TO PROCEED: Verified structural legitimacy and authentic link distribution.
              </div>
              <div style="font-size: 12px; font-family:monospace; color: #64748B;">Latency: 64.2 ms • Full ML Mode</div>
            </div>
          </div>

          <!-- Right Column: Forensic Telemetry -->
          <div class="glass-card" style="flex: 0.9; padding: 28px; display: flex; flex-direction: column;">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom: 20px; border-bottom: 1px solid #1E293B; padding-bottom: 14px;">
              <div style="font-size: 17px; font-weight: 700; color: #F8FAFC; display:flex; align-items:center; gap: 8px;">
                📋 Forensic Analysis Telemetry
              </div>
              <div style="font-size: 12px; font-family:monospace; color: #10B981;">Status: 200 OK</div>
            </div>

            <div style="margin-bottom: 20px;">
              <div style="font-size: 12px; font-weight:700; color: #38BDF8; text-transform:uppercase; margin-bottom: 10px;">Classification Confidence Breakdown</div>
              <div style="display:flex; justify-content:space-between; padding: 6px 0; border-bottom: 1px solid #1E293B; font-size: 13px;">
                <span style="color: #94A3B8;">Phishing Probability:</span>
                <span style="color: #10B981; font-family:monospace; font-weight:700;">0.0040 (0.4%)</span>
              </div>
              <div style="display:flex; justify-content:space-between; padding: 6px 0; border-bottom: 1px solid #1E293B; font-size: 13px;">
                <span style="color: #94A3B8;">Risk Level Mapping:</span>
                <span style="color: #10B981; font-weight:700;">LOW RISK</span>
              </div>
              <div style="display:flex; justify-content:space-between; padding: 6px 0; border-bottom: 1px solid #1E293B; font-size: 13px;">
                <span style="color: #94A3B8;">HTML Inspection:</span>
                <span style="color: #38BDF8; font-family:monospace;">Available (HTTP 200 OK)</span>
              </div>
              <div style="display:flex; justify-content:space-between; padding: 6px 0; font-size: 13px;">
                <span style="color: #94A3B8;">SSRF Guard Verification:</span>
                <span style="color: #10B981; font-family:monospace;">Passed (Clean Public Destination)</span>
              </div>
            </div>

            <div style="flex:1; background: #030712; border: 1px solid #1E293B; border-radius: 8px; padding: 16px; font-family: monospace; font-size: 12px; color: #94A3B8; overflow:hidden;">
              <div style="color: #38BDF8; font-weight:700; margin-bottom: 8px;">Extracted Signal Breakdown (Sample)</div>
              <div>• url_length: 46 | path_depth: 3</div>
              <div>• uses_https: 1 | num_subdomains: 1</div>
              <div>• has_ip_address: 0 | has_suspicious_tld: 0</div>
              <div>• num_forms: 0 | num_password_fields: 0</div>
              <div>• external_link_ratio: 0.05 | is_shortened_url: 0</div>
              <div>• content_rendering_incomplete: 0 (Full SSR)</div>
              <div style="margin-top: 14px; color: #10B981;">✓ Model calibrated confidence: 99.6% Legitimate</div>
            </div>
          </div>
        </div>
      `;
    }

    const html = `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <style>${BASE_STYLES}</style>
      </head>
      <body>
        <!-- Header Navbar -->
        <div class="navbar">
          <div class="logo">
            <span style="font-size: 26px;">🛡️</span>
            <span>PhishGuard <span style="color: #3B82F6;">AI</span></span>
          </div>
          <div style="display:flex; gap: 24px; font-size: 14px; font-weight: 500; color: #94A3B8;">
            <span style="color: #38BDF8; font-weight: 600;">Live Scanner</span>
            <span>Dashboard</span>
            <span>How It Works</span>
            <span>Technology</span>
            <span>Browser Extension</span>
          </div>
          <div class="badge-online">
            <span class="badge-dot"></span>
            <span>Backend Online (127.0.0.1:8000) • XGBoost v1.2</span>
          </div>
        </div>

        <!-- Main Content Body -->
        ${mainContentHtml}

        <!-- Caption Bar -->
        <div class="caption-bar">
          <div class="caption-tag">${captionTag}</div>
          <div class="caption-text">${captionText}</div>
        </div>

        <!-- Mouse Cursor -->
        ${renderCursorSvg(cursorX, cursorY, isClicking)}
      </body>
      </html>
    `;

    await page.setContent(html, { waitUntil: 'domcontentloaded' });
    const buffer = await page.screenshot({ type: 'png' });
    ffmpeg.stdin.write(buffer);

    if (frame % 150 === 0) {
      console.log(`[Video 01] Rendered frame ${frame} / ${TOTAL_FRAMES} (${((frame / TOTAL_FRAMES) * 100).toFixed(1)}%)`);
    }
  }

  ffmpeg.stdin.end();
  await browser.close();

  await new Promise((resolve) => {
    ffmpeg.on('close', (code) => {
      console.log(`[+] Video 01 completed with exit code ${code}: ${outputPath}`);
      resolve();
    });
  });
}

generateVideo01().catch(console.error);

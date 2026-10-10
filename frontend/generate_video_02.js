import puppeteer from 'puppeteer';
import { spawn } from 'child_process';
import path from 'path';
import { fileURLToPath } from 'url';
import { FFMPEG_PATH, VIDEOS_DIR, BASE_STYLES, renderCursorSvg, easeInOutQuad } from './video_helpers.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function generateVideo02() {
  const outputPath = path.join(VIDEOS_DIR, '02_web_suspicious_high_risk_scans.mp4');
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

  const urlA = 'http://unverified-fast-news.biz/article/2026';
  const urlB = 'http://192.168.1.50/secure-login/account-verification';

  for (let frame = 0; frame < TOTAL_FRAMES; frame++) {
    const tSec = frame / FPS;

    let part = 'A'; // 'A' (0-28s) or 'B' (28-60s)
    let state = 'typing';
    let typedText = '';
    let cursorX = 960;
    let cursorY = 800;
    let isClicking = false;
    let gaugeProgress = 0;
    let captionTag = 'PART A: SUSPICIOUS';
    let captionText = '';

    if (tSec < 28) {
      // PART A: Suspicious URL
      part = 'A';
      if (tSec < 6) {
        // Typing URL A
        state = 'typing';
        captionTag = 'PART A: SUSPICIOUS';
        captionText = 'Part A: Entering unverified suspicious domain: http://unverified-fast-news.biz/article/2026';
        const prog = Math.min(1, tSec / 5);
        typedText = urlA.substring(0, Math.floor(prog * urlA.length));
        cursorX = 350 + typedText.length * 14;
        cursorY = 278;
      } else if (tSec < 9) {
        // Click Analyze
        state = 'click';
        typedText = urlA;
        captionTag = 'PART A: ANALYZE';
        captionText = 'Submitting suspicious URL. Backend detects unverified TLD (.biz) and plain HTTP transport.';
        cursorX = 1080;
        cursorY = 278;
        if (tSec >= 7.5 && tSec < 7.9) isClicking = true;
      } else if (tSec < 14) {
        // Analyzing
        state = 'analyzing';
        typedText = urlA;
        captionTag = 'DEGRADED MODE';
        captionText = 'HTML is unreachable. PhishGuard AI activates ethical score dampening (max 48% threat boundary).';
        cursorX = 1080;
        cursorY = 278;
      } else {
        // Result Part A
        state = 'result_A';
        typedText = urlA;
        captionTag = 'PART A: VERDICT';
        captionText = 'Verdict: SUSPICIOUS (48.0% Risk). Unencrypted HTTP, multi-token hyphenation, unreachable DOM.';
        const gaugeProg = Math.min(1, (tSec - 14) / 2);
        gaugeProgress = 0.48 * easeInOutQuad(gaugeProg);
        cursorX = 400 + Math.sin((tSec - 14) * 0.8) * 120;
        cursorY = 550;
      }
    } else {
      // PART B: High-Risk Phishing
      part = 'B';
      const tB = tSec - 28; // 0 to 32s
      if (tB < 6) {
        // Typing URL B
        state = 'typing';
        captionTag = 'PART B: HIGH-RISK';
        captionText = 'Part B: Entering high-risk SSRF & phishing lure: http://192.168.1.50/secure-login/account-verification';
        const prog = Math.min(1, tB / 5);
        typedText = urlB.substring(0, Math.floor(prog * urlB.length));
        cursorX = 350 + typedText.length * 14;
        cursorY = 278;
      } else if (tB < 9) {
        // Click Analyze
        state = 'click';
        typedText = urlB;
        captionTag = 'PART B: ANALYZE';
        captionText = 'Target targets private RFC 1918 internal network with credential harvesting keywords.';
        cursorX = 1080;
        cursorY = 278;
        if (tB >= 7.5 && tB < 7.9) isClicking = true;
      } else if (tB < 14) {
        // Analyzing & Defense Triggered
        state = 'analyzing';
        typedText = urlB;
        captionTag = 'SSRF DEFENSE TRIGGERED';
        captionText = 'SSRF Perimeter Guard blocks outbound socket to 192.168.1.50. Threat escalated by auth signals.';
        cursorX = 1080;
        cursorY = 278;
      } else {
        // Result Part B
        state = 'result_B';
        typedText = urlB;
        captionTag = 'PART B: CRITICAL THREAT';
        captionText = 'Verdict: CRITICAL THREAT (91.1% Risk). Raw IP obfuscation + SSRF attempt + credential keywords.';
        const gaugeProg = Math.min(1, (tB - 14) / 2);
        gaugeProgress = 0.911 * easeInOutQuad(gaugeProg);
        cursorX = 400 + Math.sin((tB - 14) * 0.8) * 120;
        cursorY = 550;
      }
    }

    let mainContentHtml = '';

    if (state === 'typing' || state === 'click') {
      mainContentHtml = `
        <div style="flex:1; display:flex; flex-direction:column; align-items:center; justify-content:center; padding: 40px 100px;">
          <div style="text-align:center; max-width:800px; margin-bottom: 40px;">
            <div style="display:inline-block; padding: 6px 14px; border-radius: 999px; background: ${part === 'A' ? 'rgba(245, 158, 11, 0.15)' : 'rgba(239, 68, 68, 0.15)'}; border: 1px solid ${part === 'A' ? 'rgba(245, 158, 11, 0.4)' : 'rgba(239, 68, 68, 0.4)'}; color: ${part === 'A' ? '#F59E0B' : '#EF4444'}; font-weight: 700; font-size: 13px; margin-bottom: 16px;">
              ${part === 'A' ? 'TEST CASE A: SUSPICIOUS & DEGRADED MODE' : 'TEST CASE B: HIGH-RISK SSRF PHISHING LURE'}
            </div>
            <h1 style="font-size: 40px; font-weight: 800; letter-spacing:-1px; margin-bottom: 12px; color: #FFFFFF;">
              ${part === 'A' ? 'Suspicious Domain Risk Assessment' : 'Critical Threat & SSRF Defense Interception'}
            </h1>
          </div>

          <div class="glass-card" style="width: 100%; max-width: 900px; padding: 12px 16px; display: flex; align-items: center; gap: 14px; box-shadow: 0 20px 40px rgba(0,0,0,0.5);">
            <div style="color: #64748B; padding-left: 10px; font-size: 20px;">🌐</div>
            <div style="flex: 1; font-size: 17px; font-family: monospace; color: #F8FAFC;">
              ${typedText}<span style="border-right: 2px solid ${part === 'A' ? '#F59E0B' : '#EF4444'};"></span>
            </div>
            <button style="background: ${isClicking ? (part === 'A' ? '#D97706' : '#DC2626') : (part === 'A' ? '#F59E0B' : '#EF4444')}; color: white; border: none; padding: 14px 28px; border-radius: 10px; font-size: 16px; font-weight: 700; cursor: pointer; transform: scale(${isClicking ? '0.96' : '1.0'});">
              ⚡ Analyze URL
            </button>
          </div>
        </div>
      `;
    } else if (state === 'analyzing') {
      mainContentHtml = `
        <div style="flex:1; display:flex; flex-direction:column; align-items:center; justify-content:center; padding: 40px 100px;">
          <div class="glass-card" style="width: 100%; max-width: 900px; padding: 36px 40px;">
            <div style="font-size: 20px; font-weight: 700; color: #F8FAFC; margin-bottom: 24px; display:flex; align-items:center; gap: 12px;">
              <span style="font-size:24px;">${part === 'A' ? '⚠️' : '🚨'}</span>
              <span>Forensic Engine Evaluating: <span style="font-family:monospace; color:${part === 'A' ? '#F59E0B' : '#EF4444'};">${typedText}</span></span>
            </div>
            <div style="background: rgba(30, 41, 59, 0.6); border: 1px solid #334155; border-radius: 10px; padding: 20px; font-size: 15px; color: #E2E8F0; line-height: 1.6;">
              ${part === 'A' 
                ? '• DNS Resolution Error: Remote host unreachable.<br>• Degraded Mode: Extracting 23 lexical signals only.<br>• Score Policy: Enforcing ethical upper bound of 48% (Suspicious) to prevent false-positive block.' 
                : '• Host validation: Target 192.168.1.50 is an RFC 1918 Private IP.<br>• <strong style="color:#EF4444;">SSRF Perimeter Defense: Socket connection BLOCKED.</strong><br>• Lexical keywords: Found sensitive tokens [login, secure, verify].<br>• Model probability: Escalated to 91.1% Critical Threat.'}
            </div>
          </div>
        </div>
      `;
    } else if (state === 'result_A') {
      // Result A: Suspicious
      mainContentHtml = `
        <div style="flex:1; display:flex; padding: 30px 40px; gap: 30px; height: calc(1080px - 150px);">
          <div class="glass-card" style="flex: 1.3; padding: 28px 32px; display: flex; flex-direction: column; justify-content: space-between;">
            <div>
              <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom: 20px;">
                <div style="font-size: 18px; font-weight: 700; color: #F8FAFC;">🔬 Suspicious Destination Analysis</div>
                <div style="font-size: 13px; font-family:monospace; color: #F59E0B; background: rgba(245,158,11,0.1); padding: 4px 10px; border-radius: 6px; border:1px solid rgba(245,158,11,0.3);">
                  Verdict: SUSPICIOUS (48.0%)
                </div>
              </div>

              <div style="background: rgba(30, 41, 59, 0.7); border: 1px solid #334155; border-radius: 8px; padding: 12px 16px; display:flex; align-items:center; gap: 12px; margin-bottom: 24px;">
                <span style="color: #F59E0B; font-size: 18px;">⚠️</span>
                <span style="font-family:monospace; font-size: 16px; color: #F8FAFC; flex:1;">${typedText}</span>
              </div>

              <div style="background: linear-gradient(135deg, rgba(245, 158, 11, 0.1), rgba(15, 23, 42, 0.8)); border: 1px solid rgba(245, 158, 11, 0.4); border-radius: 12px; padding: 24px; display:flex; justify-content:space-between; align-items:center; margin-bottom: 24px;">
                <div>
                  <div style="font-size: 12px; font-weight:800; letter-spacing:1px; color:#F59E0B; text-transform:uppercase; margin-bottom: 6px;">VERDICT: SUSPICIOUS DOMAIN</div>
                  <div style="font-size: 26px; font-weight:800; color:#FFFFFF; margin-bottom: 8px;">Deceptive Or Unverified Site</div>
                  <div style="font-size: 14px; color: #94A3B8;">Unencrypted HTTP transport. Unreachable host with bounded risk dampening applied.</div>
                </div>

                <div style="position:relative; width: 110px; height: 110px; display:flex; align-items:center; justify-content:center;">
                  <svg width="110" height="110" viewBox="0 0 100 100">
                    <circle cx="50" cy="50" r="42" stroke="#1E293B" stroke-width="10" fill="none"/>
                    <circle cx="50" cy="50" r="42" stroke="#F59E0B" stroke-width="10" fill="none" stroke-dasharray="264" stroke-dashoffset="${264 - (264 * gaugeProgress)}" stroke-linecap="round" transform="rotate(-90 50 50)"/>
                  </svg>
                  <div style="position:absolute; text-align:center;">
                    <div style="font-size: 20px; font-weight: 800; color: #F59E0B;">48.0%</div>
                    <div style="font-size: 9px; color: #64748B; font-weight:700;">RISK SCORE</div>
                  </div>
                </div>
              </div>

              <div style="display:grid; grid-template-columns: 1fr 1fr; gap: 14px; margin-bottom: 20px;">
                <div style="background: rgba(30, 41, 59, 0.4); border: 1px solid #334155; padding: 14px 16px; border-radius: 8px;">
                  <div style="font-size: 11px; color: #94A3B8; text-transform:uppercase; font-weight:700; margin-bottom: 4px;">HTTPS Encryption</div>
                  <div style="font-size: 15px; font-weight: 700; color: #EF4444;">Insecure Plain HTTP (No TLS)</div>
                </div>
                <div style="background: rgba(30, 41, 59, 0.4); border: 1px solid #334155; padding: 14px 16px; border-radius: 8px;">
                  <div style="font-size: 11px; color: #94A3B8; text-transform:uppercase; font-weight:700; margin-bottom: 4px;">Top-Level Domain (TLD)</div>
                  <div style="font-size: 15px; font-weight: 700; color: #F59E0B;">.biz (Commercial / Low Volume)</div>
                </div>
                <div style="background: rgba(30, 41, 59, 0.4); border: 1px solid #334155; padding: 14px 16px; border-radius: 8px;">
                  <div style="font-size: 11px; color: #94A3B8; text-transform:uppercase; font-weight:700; margin-bottom: 4px;">Hyphens in Domain</div>
                  <div style="font-size: 15px; font-weight: 700; color: #F59E0B;">2 Hyphens (unverified-fast-news)</div>
                </div>
                <div style="background: rgba(30, 41, 59, 0.4); border: 1px solid #334155; padding: 14px 16px; border-radius: 8px;">
                  <div style="font-size: 11px; color: #94A3B8; text-transform:uppercase; font-weight:700; margin-bottom: 4px;">Inspection State</div>
                  <div style="font-size: 15px; font-weight: 700; color: #F59E0B;">URL Lexical Only (Degraded)</div>
                </div>
              </div>

              <div style="display:flex; flex-direction:column; gap: 8px;">
                <div style="background: rgba(245, 158, 11, 0.08); border-left: 3px solid #F59E0B; padding: 8px 12px; font-size: 13px; color: #E2E8F0;">
                  ⚠️ Connection does not use secure HTTPS encryption; transmitted data is visible in plaintext.
                </div>
                <div style="background: rgba(245, 158, 11, 0.08); border-left: 3px solid #F59E0B; padding: 8px 12px; font-size: 13px; color: #E2E8F0;">
                  ⚠️ Live HTML content could not be inspected (DNS resolution error); threat level is bounded to Suspicious.
                </div>
              </div>
            </div>

            <div style="background: rgba(15, 23, 42, 0.9); border: 1px solid #334155; border-radius: 8px; padding: 12px 18px; display:flex; justify-content:space-between; align-items:center;">
              <div style="font-size: 13px; color: #94A3B8;">
                <strong style="color: #F59E0B;">Action:</strong> EXERCISE CAUTION: Inspect the domain address bar carefully.
              </div>
              <div style="font-size: 12px; font-family:monospace; color: #64748B;">Latency: 18.4 ms • Degraded Mode</div>
            </div>
          </div>

          <div class="glass-card" style="flex: 0.9; padding: 28px; display: flex; flex-direction: column;">
            <div style="font-size: 16px; font-weight:700; color: #F8FAFC; margin-bottom: 16px;">📑 Degraded-Mode Calibration Policy</div>
            <div style="background: rgba(30, 41, 59, 0.5); border: 1px solid #334155; border-radius: 8px; padding: 16px; font-size: 13px; color: #94A3B8; line-height: 1.6; margin-bottom: 16px;">
              <strong style="color: #F59E0B;">Why is this classified as Suspicious rather than Phishing?</strong><br>
              When a webpage is offline or unreachable, PhishGuard AI prevents false-positive blocks by capping the risk score at 48% (Medium/Suspicious), unless raw IP or blatant auth-theft keywords are detected.
            </div>
            <div style="flex:1; background: #030712; border: 1px solid #1E293B; border-radius: 8px; padding: 16px; font-family: monospace; font-size: 12px; color: #94A3B8;">
              <div style="color: #F59E0B; font-weight:700; margin-bottom: 8px;">Extracted Signal Vector</div>
              <div>• domain_length: 24 | path_length: 13</div>
              <div>• uses_https: 0 | num_hyphens: 2</div>
              <div>• html_available: False | parse_error: 1</div>
              <div>• raw_prob: 0.5210 -> adjusted_prob: 0.4800</div>
            </div>
          </div>
        </div>
      `;
    } else {
      // Result B: High-Risk Phishing
      mainContentHtml = `
        <div style="flex:1; display:flex; padding: 30px 40px; gap: 30px; height: calc(1080px - 150px);">
          <div class="glass-card" style="flex: 1.3; padding: 28px 32px; display: flex; flex-direction: column; justify-content: space-between;">
            <div>
              <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom: 20px;">
                <div style="font-size: 18px; font-weight: 700; color: #EF4444; display:flex; align-items:center; gap: 8px;">
                  🚨 High-Risk Phishing Threat Result
                </div>
                <div style="font-size: 13px; font-family:monospace; color: #EF4444; background: rgba(239,68,68,0.1); padding: 4px 10px; border-radius: 6px; border:1px solid rgba(239,68,68,0.3);">
                  Verdict: PHISHING (91.1%)
                </div>
              </div>

              <div style="background: rgba(30, 41, 59, 0.7); border: 1px solid #334155; border-radius: 8px; padding: 12px 16px; display:flex; align-items:center; gap: 12px; margin-bottom: 24px;">
                <span style="color: #EF4444; font-size: 18px;">🚫</span>
                <span style="font-family:monospace; font-size: 16px; color: #F8FAFC; flex:1;">${typedText}</span>
              </div>

              <div style="background: linear-gradient(135deg, rgba(239, 68, 68, 0.15), rgba(15, 23, 42, 0.8)); border: 1px solid rgba(239, 68, 68, 0.5); border-radius: 12px; padding: 24px; display:flex; justify-content:space-between; align-items:center; margin-bottom: 24px;">
                <div>
                  <div style="font-size: 12px; font-weight:800; letter-spacing:1px; color:#EF4444; text-transform:uppercase; margin-bottom: 6px;">VERDICT: CRITICAL PHISHING ATTACK</div>
                  <div style="font-size: 26px; font-weight:800; color:#FFFFFF; margin-bottom: 8px;">Credential Harvesting Hazard</div>
                  <div style="font-size: 14px; color: #94A3B8;">Raw IP obfuscation with high-risk authentication lure keywords and SSRF breach attempt.</div>
                </div>

                <div style="position:relative; width: 110px; height: 110px; display:flex; align-items:center; justify-content:center;">
                  <svg width="110" height="110" viewBox="0 0 100 100">
                    <circle cx="50" cy="50" r="42" stroke="#1E293B" stroke-width="10" fill="none"/>
                    <circle cx="50" cy="50" r="42" stroke="#EF4444" stroke-width="10" fill="none" stroke-dasharray="264" stroke-dashoffset="${264 - (264 * gaugeProgress)}" stroke-linecap="round" transform="rotate(-90 50 50)"/>
                  </svg>
                  <div style="position:absolute; text-align:center;">
                    <div style="font-size: 20px; font-weight: 800; color: #EF4444;">91.1%</div>
                    <div style="font-size: 9px; color: #64748B; font-weight:700;">RISK SCORE</div>
                  </div>
                </div>
              </div>

              <div style="display:grid; grid-template-columns: 1fr 1fr; gap: 14px; margin-bottom: 20px;">
                <div style="background: rgba(30, 41, 59, 0.4); border: 1px solid #334155; padding: 14px 16px; border-radius: 8px;">
                  <div style="font-size: 11px; color: #94A3B8; text-transform:uppercase; font-weight:700; margin-bottom: 4px;">Raw IP Host Obfuscation</div>
                  <div style="font-size: 15px; font-weight: 700; color: #EF4444;">YES (192.168.1.50)</div>
                </div>
                <div style="background: rgba(30, 41, 59, 0.4); border: 1px solid #334155; padding: 14px 16px; border-radius: 8px;">
                  <div style="font-size: 11px; color: #94A3B8; text-transform:uppercase; font-weight:700; margin-bottom: 4px;">Auth Lure Keywords</div>
                  <div style="font-size: 15px; font-weight: 700; color: #EF4444;">DETECTED (login, secure, verify)</div>
                </div>
                <div style="background: rgba(30, 41, 59, 0.4); border: 1px solid #334155; padding: 14px 16px; border-radius: 8px;">
                  <div style="font-size: 11px; color: #94A3B8; text-transform:uppercase; font-weight:700; margin-bottom: 4px;">HTTPS Encryption</div>
                  <div style="font-size: 15px; font-weight: 700; color: #EF4444;">INSECURE (HTTP Plaintext)</div>
                </div>
                <div style="background: rgba(30, 41, 59, 0.4); border: 1px solid #334155; padding: 14px 16px; border-radius: 8px;">
                  <div style="font-size: 11px; color: #94A3B8; text-transform:uppercase; font-weight:700; margin-bottom: 4px;">SSRF Perimeter Guard</div>
                  <div style="font-size: 15px; font-weight: 700; color: #EF4444;">BLOCKED (RFC 1918 Private IP)</div>
                </div>
              </div>

              <div style="display:flex; flex-direction:column; gap: 8px;">
                <div style="background: rgba(239, 68, 68, 0.08); border-left: 3px solid #EF4444; padding: 8px 12px; font-size: 13px; color: #E2E8F0;">
                  🚫 URL uses a raw IP address instead of a standard domain name to evade reputation feeds.
                </div>
                <div style="background: rgba(239, 68, 68, 0.08); border-left: 3px solid #EF4444; padding: 8px 12px; font-size: 13px; color: #E2E8F0;">
                  🚫 Live HTML content blocked by SSRF Guard (Restricted internal IP); threat score escalated by ML signals.
                </div>
              </div>
            </div>

            <div style="background: rgba(15, 23, 42, 0.9); border: 1px solid #334155; border-radius: 8px; padding: 12px 18px; display:flex; justify-content:space-between; align-items:center;">
              <div style="font-size: 13px; color: #94A3B8;">
                <strong style="color: #EF4444;">Action:</strong> CRITICAL THREAT: Do NOT enter credentials, passwords, or personal details.
              </div>
              <div style="font-size: 12px; font-family:monospace; color: #64748B;">Latency: 17.0 ms • Threat Escalated</div>
            </div>
          </div>

          <div class="glass-card" style="flex: 0.9; padding: 28px; display: flex; flex-direction: column;">
            <div style="font-size: 16px; font-weight:700; color: #EF4444; margin-bottom: 16px;">🛡️ SSRF Security & Threat Escalation</div>
            <div style="background: rgba(239, 68, 68, 0.1); border: 1px solid rgba(239, 68, 68, 0.3); border-radius: 8px; padding: 16px; font-size: 13px; color: #FCA5A5; line-height: 1.6; margin-bottom: 16px;">
              <strong>Why did SSRF Defense trigger?</strong><br>
              Target host 192.168.1.50 belongs to the RFC 1918 private subnet (Class C internal LAN). Outbound socket creation was blocked to prevent backend abuse.
            </div>
            <div style="flex:1; background: #030712; border: 1px solid #1E293B; border-radius: 8px; padding: 16px; font-family: monospace; font-size: 12px; color: #94A3B8;">
              <div style="color: #EF4444; font-weight:700; margin-bottom: 8px;">Forensic Telemetry Vector</div>
              <div>• has_ip_address: 1 | has_suspicious_keywords: 1</div>
              <div>• domain_length: 12 | path_length: 33</div>
              <div>• uses_https: 0 | ssrf_protection: Blocked</div>
              <div>• is_phishing: True | confidence: 0.9113</div>
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
        <div class="navbar">
          <div class="logo">
            <span style="font-size: 26px;">🛡️</span>
            <span>PhishGuard <span style="color: #3B82F6;">AI</span></span>
          </div>
          <div style="display:flex; gap: 24px; font-size: 14px; font-weight: 500; color: #94A3B8;">
            <span>Live Scanner</span>
            <span style="color: #38BDF8; font-weight: 600;">Comparative Forensics</span>
            <span>Dashboard</span>
            <span>Technology</span>
            <span>Extension</span>
          </div>
          <div class="badge-online" style="border-color: ${part === 'A' ? 'rgba(245,158,11,0.4)' : 'rgba(239,68,68,0.4)'}; background: ${part === 'A' ? 'rgba(245,158,11,0.1)' : 'rgba(239,68,68,0.1)'}; color: ${part === 'A' ? '#F59E0B' : '#EF4444'};">
            <span class="badge-dot" style="background: ${part === 'A' ? '#F59E0B' : '#EF4444'}; box-shadow: 0 0 8px ${part === 'A' ? '#F59E0B' : '#EF4444'};"></span>
            <span>${part === 'A' ? 'Degraded Mode Active • Calibrated Bound (≤48%)' : '🚨 SSRF Perimeter Defense Triggered'}</span>
          </div>
        </div>

        ${mainContentHtml}

        <div class="caption-bar">
          <div class="caption-tag" style="background: ${part === 'A' ? '#F59E0B' : '#EF4444'};">${captionTag}</div>
          <div class="caption-text">${captionText}</div>
        </div>

        ${renderCursorSvg(cursorX, cursorY, isClicking)}
      </body>
      </html>
    `;

    await page.setContent(html, { waitUntil: 'domcontentloaded' });
    const buffer = await page.screenshot({ type: 'png' });
    ffmpeg.stdin.write(buffer);

    if (frame % 200 === 0) {
      console.log(`[Video 02] Rendered frame ${frame} / ${TOTAL_FRAMES} (${((frame / TOTAL_FRAMES) * 100).toFixed(1)}%)`);
    }
  }

  ffmpeg.stdin.end();
  await browser.close();

  await new Promise((resolve) => {
    ffmpeg.on('close', (code) => {
      console.log(`[+] Video 02 completed with exit code ${code}: ${outputPath}`);
      resolve();
    });
  });
}

generateVideo02().catch(console.error);

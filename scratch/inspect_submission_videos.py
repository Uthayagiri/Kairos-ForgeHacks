import os
import cv2

video_dir = r"C:\Users\Udhaya\S5_Phishing_Detector\forgehacks_submission\videos"
expected_files = [
    "01_web_legitimate_scan.mp4",
    "02_web_suspicious_high_risk_scans.mp4",
    "03_extension_url_scanning.mp4",
    "04_extension_pre_navigation_warning.mp4",
    "05_full_system_demonstration.mp4"
]

print("=" * 70)
print("PHISHGUARD AI - FORGEHACKS VIDEO SUBMISSION INSPECTION")
print("=" * 70)

for filename in expected_files:
    filepath = os.path.join(video_dir, filename)
    if os.path.exists(filepath):
        cap = cv2.VideoCapture(filepath)
        fps = cap.get(cv2.CAP_PROP_FPS)
        frame_count = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
        width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
        height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
        duration = frame_count / fps if fps > 0 else 0
        size_mb = os.path.getsize(filepath) / (1024 * 1024)
        cap.release()
        print(f"[OK] {filename}:")
        print(f"     Resolution: {width}x{height} (16:9 1080p)")
        print(f"     FPS: {fps:.1f} | Frames: {frame_count}")
        print(f"     Duration: {duration:.2f} seconds ({int(duration//60)}m {int(duration%60)}s)")
        print(f"     File Size: {size_mb:.2f} MB")
    else:
        print(f"[MISSING] {filename}: (Not yet generated)")

print("=" * 70)

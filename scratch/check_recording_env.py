import sys
import shutil
import subprocess

print("Python version:", sys.version)
ffmpeg_path = shutil.which("ffmpeg")
print("ffmpeg path:", ffmpeg_path)

try:
    import playwright
    print("Playwright installed:", playwright.__file__)
except ImportError as e:
    print("Playwright not installed:", e)

try:
    import cv2
    print("OpenCV installed:", cv2.__file__)
except ImportError:
    print("OpenCV not installed")

try:
    import moviepy
    print("MoviePy installed")
except ImportError:
    print("MoviePy not installed")

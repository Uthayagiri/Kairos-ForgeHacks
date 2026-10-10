import imageio_ffmpeg
import cv2
import numpy as np

print("imageio_ffmpeg exe:", imageio_ffmpeg.get_ffmpeg_exe())
print("cv2 version:", cv2.__version__)

# Quick test of VideoWriter
fourcc = cv2.VideoWriter_fourcc(*'mp4v')
out = cv2.VideoWriter("scratch/test.mp4", fourcc, 30.0, (640, 480))
for i in range(30):
    frame = np.zeros((480, 640, 3), dtype=np.uint8)
    frame[:, :, 0] = i * 8
    out.write(frame)
out.release()
print("Test video written successfully!")

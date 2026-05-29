import threading
import cv2
import os


class CameraStream:
    def __init__(self):
        self.mode = "local"
        self.source = "0"
        self.cap = None
        self.lock = threading.Lock()
        self.frame = None
        self.running = False

    def configure(self, mode: str, source: str):
        mode = (mode or "local").lower()
        self.mode = "public" if mode == "public" else "local"
        self.source = source or "0"
        if self.running:
            self.stop()

    def _resolve_source(self):
        if self.mode == "public":
            return self.source
        try:
            return int(self.source)
        except (TypeError, ValueError):
            return 0

    def start(self):
        if self.running:
            return True

        source = self._resolve_source()

        if self.mode == "public":
            # Use FFmpeg backend for RTSP/HTTP streams
            self.cap = cv2.VideoCapture(source, cv2.CAP_FFMPEG)
            # Set a 10-second open timeout so Railway doesn't hang
            self.cap.set(cv2.CAP_PROP_OPEN_TIMEOUT_MSEC, 10000)
            self.cap.set(cv2.CAP_PROP_READ_TIMEOUT_MSEC, 10000)
        else:
            self.cap = cv2.VideoCapture(source)

        if not self.cap.isOpened():
            if self.cap:
                self.cap.release()
            self.cap = None
            return False

        self.running = True
        thread = threading.Thread(target=self._read_frames, daemon=True)
        thread.start()
        return True

    def _read_frames(self):
        consecutive_failures = 0
        while self.running and self.cap:
            ret, frame = self.cap.read()
            if not ret:
                consecutive_failures += 1
                # Stop after 30 consecutive failures to avoid infinite spin
                if consecutive_failures >= 30:
                    self.running = False
                    break
                continue
            consecutive_failures = 0
            with self.lock:
                self.frame = frame

    def get_frame(self):
        with self.lock:
            if self.frame is None or self.cap is None:
                return None
            ret, buffer = cv2.imencode(".jpg", self.frame)
            return buffer.tobytes() if ret else None

    def stop(self):
        self.running = False
        if self.cap:
            self.cap.release()
            self.cap = None
            self.frame = None

    def get_status(self):
        return {
            "mode": self.mode,
            "source": self.source,
            "streaming": self.running and self.cap is not None,
        }

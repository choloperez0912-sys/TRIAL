import threading
import time
import cv2


class CameraStream:
    def __init__(self):
        self.mode = "local"
        self.source = "0"
        self.cap = None
        self.lock = threading.Lock()
        self.frame = None
        self.running = False
        self._frame_time = 0  # timestamp of last captured frame

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
            self.cap = cv2.VideoCapture(source, cv2.CAP_FFMPEG)
            self.cap.set(cv2.CAP_PROP_OPEN_TIMEOUT_MSEC, 10000)
            self.cap.set(cv2.CAP_PROP_READ_TIMEOUT_MSEC, 10000)
            self.cap.set(cv2.CAP_PROP_BUFFERSIZE, 1)
        else:
            self.cap = cv2.VideoCapture(source)
            self.cap.set(cv2.CAP_PROP_BUFFERSIZE, 1)

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
                if consecutive_failures >= 30:
                    self.running = False
                    break
                time.sleep(0.05)
                continue
            consecutive_failures = 0
            with self.lock:
                self.frame = frame
                self._frame_time = time.time()

    def get_frame(self):
        with self.lock:
            if self.frame is None or self.cap is None:
                return None, 0
            ret, buffer = cv2.imencode(
                ".jpg", self.frame,
                [cv2.IMWRITE_JPEG_QUALITY, 85]
            )
            return (buffer.tobytes() if ret else None), self._frame_time

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

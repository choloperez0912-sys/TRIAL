import threading
import cv2


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
        while self.running and self.cap:
            ret, frame = self.cap.read()
            if not ret:
                break
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

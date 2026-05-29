FROM python:3.13-slim

ENV PYTHONUNBUFFERED=1
ENV PORT=8080
ENV PATH="/usr/local/bin:$PATH"
ENV OPENCV_FFMPEG_CAPTURE_OPTIONS="rtsp_transport;tcp"

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        libgl1 \
        libglib2.0-0 \
        libsm6 \
        libxext6 \
        libxrender-dev \
        libgomp1 \
        libgthread-2.0-0 \
        ffmpeg \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
RUN pip show gunicorn && which gunicorn

COPY . /app

EXPOSE 8080

CMD ["python", "-m", "gunicorn", "app:app", "--worker-class=gthread", "--workers=1", "--threads=4", "--bind", "0.0.0.0:8080", "--timeout", "120", "--graceful-timeout", "30"]

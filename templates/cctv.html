{% extends 'base.html' %}
{% block content %}
<div class="row gy-4">
  <div class="col-12">
    <div class="card shadow-sm border-0">
      <div class="card-body">
        <div class="d-flex justify-content-between align-items-start mb-3">
          <div>
            <h4 class="card-title mb-1">Live CCTV Feed</h4>
            <p class="text-muted mb-0">{{ camera_mode|capitalize }} camera mode • Source: {{ camera_source }}</p>
          </div>
          <div>
            {% if stream_ok %}
            <span class="badge bg-success">Live</span>
            {% else %}
            <span class="badge bg-danger">Offline</span>
            {% endif %}
          </div>
        </div>

        <div class="stream-frame mb-4">
          <img src="{{ url_for('stream_feed') }}" alt="Live CCTV feed" class="img-fluid rounded" />
        </div>

        <form method="post" class="row g-3">
          <div class="col-md-4">
            <label class="form-label">Camera Mode</label>
            <select class="form-select" name="camera_mode">
              <option value="local" {% if camera_mode == 'local' %}selected{% endif %}>Local Webcam</option>
              <option value="public" {% if camera_mode == 'public' %}selected{% endif %}>IP/Public Stream</option>
            </select>
          </div>
          <div class="col-md-8">
            <label class="form-label">Camera Source</label>
            <input class="form-control" name="camera_source" placeholder="0 for local webcam or rtsp://... for public stream" value="{{ camera_source }}" />
          </div>
          <div class="col-12 text-end">
            <button class="btn btn-primary" type="submit">Save Camera Configuration</button>
          </div>
        </form>
      </div>
    </div>
  </div>
</div>
{% endblock %}

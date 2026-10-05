FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN useradd --create-home --uid 10001 appuser

COPY requirements.txt /app/requirements.txt
COPY cloud_service/requirements.txt /app/cloud_service/requirements.txt
COPY edge_gateway/requirements.txt /app/edge_gateway/requirements.txt
COPY legacy_device/requirements.txt /app/legacy_device/requirements.txt
COPY pqc_channel/requirements.txt /app/pqc_channel/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY legacy_device /app/legacy_device
RUN chown -R appuser:appuser /app
USER appuser

CMD ["python", "-m", "legacy_device.device", "--host", "gateway", "--port", "9000", "--device-id", "dev-001", "--interval", "2"]

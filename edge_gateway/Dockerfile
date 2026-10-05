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

COPY edge_gateway /app/edge_gateway
COPY legacy_device /app/legacy_device
COPY pqc_channel /app/pqc_channel
COPY observability /app/observability
COPY edge_gateway/entrypoint.sh /usr/local/bin/gateway-entrypoint
RUN chmod 0555 /usr/local/bin/gateway-entrypoint \
    && chown -R appuser:appuser /app
USER appuser

EXPOSE 9000 9100

ENTRYPOINT ["gateway-entrypoint"]

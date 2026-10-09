# syntax=docker/dockerfile:1
# Python 3.12 on Debian bookworm
ARG PYTHON_IMAGE=public.ecr.aws/docker/library/python:3.12-slim-bookworm

FROM ${PYTHON_IMAGE} AS build
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_CACHE_DIR=1
RUN python -m venv /opt/venv
ENV PATH=/opt/venv/bin:$PATH
WORKDIR /src
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-deps .

FROM ${PYTHON_IMAGE}
ENV PATH=/opt/venv/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    HOME=/home/collector \
    ESPHOME_LOG_COLLECTOR_CONFIG=/config/config.yaml \
    ESPHOME_LOG_COLLECTOR_DATA_DIR=/data
RUN groupadd --system --gid 10001 collector \
    && useradd --system --uid 10001 --gid collector --home-dir /home/collector --create-home --shell /usr/sbin/nologin collector \
    && mkdir -p /data /config \
    && chown collector:collector /data
RUN apt-get update \
    && apt-get install --no-install-recommends -y git ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /opt/venv /opt/venv
USER collector:collector
WORKDIR /data
VOLUME ["/data"]
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD ["esphome-log-collector", "healthcheck"]
STOPSIGNAL SIGTERM
ENTRYPOINT ["esphome-log-collector"]
CMD ["run"]

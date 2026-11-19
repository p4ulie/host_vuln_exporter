FROM aquasec/trivy:0.76.2 AS trivy

FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends openssh-client \
    && rm -rf /var/lib/apt/lists/*
COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY host_vuln_exporter/ ./host_vuln_exporter/
USER 65534
# ponytail: bytecode writes would fail on the read-only root filesystem, so skip them.
ENV HOSTVULN_EXPORTER_PORT=9880 PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
EXPOSE 9880
CMD ["python", "-m", "host_vuln_exporter.exporter"]

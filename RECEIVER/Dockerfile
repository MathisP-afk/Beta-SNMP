FROM python:3.10-slim

WORKDIR /app

# Dependances systeme pour Scapy (capture reseau)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libffi-dev tcpdump && rm -rf /var/lib/apt/lists/*

# Dependances Python
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Code applicatif
COPY snmp_collector_unified.py .

# -u : sortie non-bufferisee (logs visibles dans docker logs)
ENTRYPOINT ["python", "-u", "snmp_collector_unified.py"]

FROM python:3.10-slim

WORKDIR /app

# Dependances systeme (libpq-dev pour psycopg2)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libffi-dev libpq-dev dos2unix && rm -rf /var/lib/apt/lists/*

# Dependances Python
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Code applicatif
COPY snmp_database_postgre.py snmp_api_improved_postgre.py snmp_gui_web.py sms_alerter.py ./
COPY snmp_sender.py init_db.py ./

# Repertoires
RUN mkdir -p /data /app/assets

# Script de demarrage
COPY start.sh .
RUN dos2unix start.sh && chmod +x start.sh

# Ports : API (8000) + GUI (12000)
EXPOSE 8000 12000

# Volume : logs
VOLUME ["/data"]

# Variables d'environnement par defaut
ENV LOG_DIR=/data

ENTRYPOINT ["./start.sh"]

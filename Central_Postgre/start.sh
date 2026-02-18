#!/bin/bash
set -e

# 1. Initialisation de la BDD (foreground — visible dans docker logs)
python init_db.py

# 2. Demarrage de l'API en arriere-plan
echo "Demarrage de l'API SNMP (port ${API_PORT:-8000})..."
python snmp_api_improved_postgre.py &
API_PID=$!

# 3. Demarrage de la GUI en arriere-plan
echo "Demarrage de la GUI SNMP (port ${GUI_PORT:-12000})..."
python snmp_gui_web.py &
GUI_PID=$!

# Attendre la fin de l'un des processus
wait -n $API_PID $GUI_PID
echo "Un processus s'est arrete, arret du conteneur."
kill $API_PID $GUI_PID 2>/dev/null
exit 1

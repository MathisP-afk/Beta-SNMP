from snmp_database_postgre import SNMPDatabase
db = SNMPDatabase()
cle = db.ajouter_cle_api(description='Cle admin')
print()
print('=' * 50)
print('  VOTRE CLE API :', cle)
print('=' * 50)
db.close()
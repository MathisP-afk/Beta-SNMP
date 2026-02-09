-- ===================================
-- SNMP Database Initialization Script
-- Exécuté automatiquement au démarrage du container PostgreSQL
-- ===================================

-- Table: Collectors (sources SNMP)
CREATE TABLE IF NOT EXISTS collectors (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    ip_address INET NOT NULL,
    port INT DEFAULT 161,
    snmp_user VARCHAR(255) NOT NULL,
    snmp_auth_proto VARCHAR(50) DEFAULT 'SHA',
    snmp_priv_proto VARCHAR(50) DEFAULT 'DES',
    enabled BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(ip_address, port)
);

-- Table: SNMP Data Points (mesures brutes)
CREATE TABLE IF NOT EXISTS snmp_data (
    id SERIAL PRIMARY KEY,
    collector_id INT NOT NULL REFERENCES collectors(id) ON DELETE CASCADE,
    oid VARCHAR(255) NOT NULL,
    oid_name VARCHAR(255),
    value TEXT,
    value_type VARCHAR(50),
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_snmp_data_collector_timestamp 
    ON snmp_data(collector_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_snmp_data_oid_timestamp 
    ON snmp_data(oid, timestamp);

-- Table: System Info (dernière valeur par OID par device)
CREATE TABLE IF NOT EXISTS system_info (
    id SERIAL PRIMARY KEY,
    collector_id INT NOT NULL UNIQUE REFERENCES collectors(id) ON DELETE CASCADE,
    sys_descr TEXT,
    sys_uptime BIGINT,
    sys_name VARCHAR(255),
    sys_location VARCHAR(255),
    sys_contact VARCHAR(255),
    if_number INT,
    last_update TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Table: Interface Data (données d'interface, collecte future)
CREATE TABLE IF NOT EXISTS interface_data (
    id SERIAL PRIMARY KEY,
    collector_id INT NOT NULL REFERENCES collectors(id) ON DELETE CASCADE,
    if_index INT NOT NULL,
    if_name VARCHAR(255),
    if_type INT,
    if_mtu INT,
    if_speed BIGINT,
    if_admin_status INT,
    if_oper_status INT,
    if_in_octets BIGINT,
    if_out_octets BIGINT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_interface_data_collector_if 
    ON interface_data(collector_id, if_index);

-- Table: Alerts (alertes et anomalies)
CREATE TABLE IF NOT EXISTS alerts (
    id SERIAL PRIMARY KEY,
    collector_id INT NOT NULL REFERENCES collectors(id) ON DELETE CASCADE,
    alert_type VARCHAR(50),
    message TEXT,
    severity VARCHAR(50),
    resolved BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    resolved_at TIMESTAMP
);

-- ===== DONNÉES DE TEST =====

-- Insérer le collecteur de test (SG250)
INSERT INTO collectors (name, ip_address, port, snmp_user, snmp_auth_proto, snmp_priv_proto)
VALUES ('SG250-Test', '192.168.1.39'::inet, 161, 'Alleria_W', 'SHA', 'DES')
ON CONFLICT (ip_address, port) DO NOTHING;

-- Vérification
SELECT 'Database initialized successfully!' as status;
SELECT * FROM collectors;

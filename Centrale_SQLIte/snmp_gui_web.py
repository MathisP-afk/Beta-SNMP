#!/usr/bin/env python3
"""
SNMP Monitor Application - SAE 501-502
Interface graphique Flet connectée à la base de données SQLite (snmp_database.py)

Adaptations:
✅ Authentification via BDD
✅ Recherche de paquets via BDD
✅ Dashboard avec statistiques réelles
"""

import json
import sys
import os
import flet as ft
from datetime import datetime

# Import de la classe fournie
from snmp_database import SNMPDatabase

# Import du module d'envoi SNMP (partage avec Central_Postgre)
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
try:
    from snmp_sender import send_get, send_getnext, send_set, send_trap, SNMPResult, PYSNMP_AVAILABLE
    SNMP_SENDER_AVAILABLE = True
except ImportError:
    SNMP_SENDER_AVAILABLE = False
    PYSNMP_AVAILABLE = False


class SNMPMonitorApp:
    def __init__(self):
        self.current_user = None
        self.current_page = "login"
        self.navigation_rail = None
        
        # Initialisation de la connexion BDD

        try:
            self.db = SNMPDatabase("exemple_snmp.db")
            print("✅ Connexion BDD SQLite réussie dans l'interface graphique")
        except Exception as e:
            print(f"❌ Erreur connexion SQLite: {e}")
            self.db = None

    def show_snackbar(self, page, message, bgcolor=ft.Colors.GREEN):
        """Méthode utilitaire pour afficher les SnackBars"""
        snackbar = ft.SnackBar(
            content=ft.Text(message),
            bgcolor=bgcolor,
            duration=3000,
            action="OK"
        )
        page.overlay.append(snackbar)
        snackbar.open = True
        page.update()

    def get_dashboard_stats(self):
        """Récupère les stats réelles depuis la BDD pour le dashboard"""
        if not self.db:
            return {
                "total_requests": 0, "get_requests": 0, "set_requests": 0,
                "response_requests": 0, "report_requests": 0,
                "errors": 0, "anomalies": 0, "last_update": datetime.now().strftime("%H:%M:%S")
            }
        
        try:
            cursor = self.db.connection.cursor()
            
            # Total
            cursor.execute("SELECT COUNT(*) FROM paquets_recus")
            total = cursor.fetchone()[0]
            
            # GET (approximation sur le type_pdu contenant 'Get')
            cursor.execute("SELECT COUNT(*) FROM paquets_recus WHERE type_pdu LIKE '%Get%'")
            get_req = cursor.fetchone()[0]
            
            # SET
            cursor.execute("SELECT COUNT(*) FROM paquets_recus WHERE type_pdu LIKE '%Set%'")
            set_req = cursor.fetchone()[0]
            
            # RESPONSE
            cursor.execute("SELECT COUNT(*) FROM paquets_recus WHERE UPPER(type_pdu) LIKE '%RESPONSE%'")
            response_req = cursor.fetchone()[0]

            # REPORT (SNMPv3)
            cursor.execute("SELECT COUNT(*) FROM paquets_recus WHERE UPPER(type_pdu) LIKE '%REPORT%'")
            report_req = cursor.fetchone()[0]

            # Erreurs (status != 0)
            cursor.execute("SELECT COUNT(*) FROM paquets_recus WHERE error_status != '0' AND error_status IS NOT NULL")
            errors = cursor.fetchone()[0]

            # Alertes sécurité (anomalies détectées par le collecteur)
            cursor.execute("SELECT COUNT(*) FROM paquets_recus WHERE contenu_json LIKE '%alerte_securite%'")
            anomalies = cursor.fetchone()[0]

            return {
                "total_requests": total,
                "get_requests": get_req,
                "set_requests": set_req,
                "response_requests": response_req,
                "report_requests": report_req,
                "errors": errors,
                "anomalies": anomalies,
                "last_update": datetime.now().strftime("%H:%M:%S")
            }
        except Exception as e:
            print(f"Erreur stats dashboard: {e}")
            return {"total_requests": 0, "get_requests": 0, "set_requests": 0, "response_requests": 0, "report_requests": 0, "errors": 0, "anomalies": 0, "last_update": "Erreur"}

    def get_recent_activity(self, limit=5):
        """Récupère les derniers paquets pour l'activité récente"""
        if not self.db: return []
        return self.db.lister_paquets_snmp(limite=limit)

    def get_stats_data(self):
        """Récupère les données agrégées pour les graphiques statistiques"""
        empty = {"pdu_types": [], "versions": [], "top_ips": [], "temporal": [], "top_oids": []}
        if not self.db:
            return empty
        try:
            cursor = self.db.connection.cursor()
            cursor.execute(
                "SELECT type_pdu, COUNT(*) FROM paquets_recus GROUP BY type_pdu ORDER BY COUNT(*) DESC"
            )
            pdu_types = cursor.fetchall()
            cursor.execute(
                "SELECT version_snmp, COUNT(*) FROM paquets_recus GROUP BY version_snmp ORDER BY COUNT(*) DESC"
            )
            versions = cursor.fetchall()
            cursor.execute(
                "SELECT adresse_source, COUNT(*) FROM paquets_recus "
                "GROUP BY adresse_source ORDER BY COUNT(*) DESC LIMIT 10"
            )
            top_ips = cursor.fetchall()
            cursor.execute(
                "SELECT DATE(timestamp_reception), COUNT(*) FROM paquets_recus "
                "WHERE timestamp_reception IS NOT NULL "
                "GROUP BY DATE(timestamp_reception) "
                "ORDER BY DATE(timestamp_reception) DESC LIMIT 30"
            )
            temporal = list(reversed(cursor.fetchall()))
            cursor.execute(
                "SELECT oid_racine, COUNT(*) FROM paquets_recus "
                "WHERE oid_racine IS NOT NULL AND oid_racine != '' "
                "GROUP BY oid_racine ORDER BY COUNT(*) DESC LIMIT 10"
            )
            top_oids = cursor.fetchall()
            return {
                "pdu_types": pdu_types, "versions": versions,
                "top_ips": top_ips, "temporal": temporal, "top_oids": top_oids
            }
        except Exception as e:
            print(f"Erreur stats graphiques: {e}")
            return empty

    def main(self, page: ft.Page):
        page.title = "SNMP Monitor - SAE 501-502"
        page.theme_mode = ft.ThemeMode.LIGHT
        page.window_width = 1200
        page.window_height = 800
        page.window_resizable = True
        page.padding = 0
        
        # Initialisation des stats
        self.stats = self.get_dashboard_stats()
        
        # Navigation Rail
        def create_navigation():
            self.navigation_rail = ft.NavigationRail(
                selected_index=0,
                label_type=ft.NavigationRailLabelType.ALL,
                min_width=100,
                min_extended_width=200,
                destinations=[
                    ft.NavigationRailDestination(
                        icon=ft.Icons.DASHBOARD_OUTLINED,
                        selected_icon=ft.Icons.DASHBOARD,
                        label="Dashboard"
                    ),
                    ft.NavigationRailDestination(
                        icon=ft.Icons.TRAFFIC_OUTLINED,
                        selected_icon=ft.Icons.TRAFFIC,
                        label="Traffic SNMP"
                    ),
                    ft.NavigationRailDestination(
                        icon=ft.Icons.SEND_OUTLINED,
                        selected_icon=ft.Icons.SEND,
                        label="Émettre"
                    ),
                    ft.NavigationRailDestination(
                        icon=ft.Icons.WARNING_OUTLINED,
                        selected_icon=ft.Icons.WARNING,
                        label="Anomalies"
                    ),
                    ft.NavigationRailDestination(
                        icon=ft.Icons.ANALYTICS_OUTLINED,
                        selected_icon=ft.Icons.ANALYTICS,
                        label="Statistiques"
                    ),
                ],
                on_change=self.on_navigation_change,
            )
            return self.navigation_rail
        
        # --- PAGE LOGIN CONNECTÉE BDD ---
        def create_login_page():
            username_field = ft.TextField(
                label="Nom d'utilisateur",
                prefix_icon=ft.Icons.PERSON,
                width=300,
                autofocus=True
            )
            password_field = ft.TextField(
                label="Mot de passe",
                prefix_icon=ft.Icons.LOCK,
                password=True,
                can_reveal_password=True,
                width=300
            )
            
            def login_click(e):
                user = username_field.value
                pwd = password_field.value
                
                if not user or not pwd:
                    self.show_snackbar(page, "Veuillez remplir tous les champs", ft.Colors.RED)
                    return

                # Vérification via la BDD
                if self.db and self.db.verifier_utilisateur(user, pwd):
                    self.current_user = user
                    # Mise à jour des stats au login
                    self.stats = self.get_dashboard_stats()
                    main_content.content = create_dashboard()
                    self.current_page = "dashboard"
                    page.go("/dashboard")
                    self.show_snackbar(page, f"Bienvenue, {self.current_user}!", ft.Colors.GREEN)
                else:
                    # Fallback si pas de BDD ou échec (pour test: admin/admin fonctionne si BDD vide)
                    if not self.db and user == "admin" and pwd == "admin":
                         self.current_user = user
                         page.go("/dashboard")
                         self.show_snackbar(page, "Mode HORS LIGNE (Pas de BDD)", ft.Colors.ORANGE)
                    else:
                        self.show_snackbar(page, "Identifiants invalides", ft.Colors.RED)
            
            def on_submit(e):
                login_click(e)
                
            username_field.on_submit = on_submit
            password_field.on_submit = on_submit
            
            return ft.Container(
                content=ft.Column([
                    ft.Container(height=50),
                    ft.Icon(ft.Icons.NETWORK_CHECK, size=80, color=ft.Colors.BLUE_700),
                    ft.Text("SNMP Monitor", size=32, weight=ft.FontWeight.BOLD, color=ft.Colors.BLUE_700),
                    ft.Text("SAE 501-502 - Connexion BDD", size=16, color=ft.Colors.GREY_600),
                    ft.Container(height=40),
                    ft.Card(
                        content=ft.Container(
                            content=ft.Column([
                                ft.Text("Connexion", size=20, weight=ft.FontWeight.BOLD),
                                ft.Container(height=20),
                                username_field,
                                ft.Container(height=15),
                                password_field,
                                ft.Container(height=25),
                                ft.ElevatedButton(
                                    text="Se connecter",
                                    icon=ft.Icons.LOGIN,
                                    width=300,
                                    height=45,
                                    on_click=login_click,
                                    style=ft.ButtonStyle(color=ft.Colors.WHITE, bgcolor=ft.Colors.BLUE_700)
                                ),
                            ], horizontal_alignment=ft.CrossAxisAlignment.CENTER),
                            padding=30, width=400
                        ),
                        elevation=8
                    )
                ], horizontal_alignment=ft.CrossAxisAlignment.CENTER),
                alignment=ft.alignment.center,
                expand=True,
                gradient=ft.LinearGradient(
                    colors=[ft.Colors.BLUE_50, ft.Colors.BLUE_100],
                    begin=ft.alignment.top_center,
                    end=ft.alignment.bottom_center
                )
            )
        
        # --- DASHBOARD CONNECTÉ BDD ---
        def create_dashboard():
            def update_dashboard_view(e=None):
                # Rafraîchir les données depuis la BDD
                self.stats = self.get_dashboard_stats()
                # Recréer la vue (méthode brutale mais efficace pour mettre à jour tous les compteurs)
                main_content.content = create_dashboard()
                page.update()
                self.show_snackbar(page, "Données actualisées depuis la BDD", ft.Colors.GREEN)

            # Construction de la liste d'activité récente
            recent_rows = []
            recent_packets = self.get_recent_activity(5)
            
            for pkt in recent_packets:
                icon = ft.Icons.HELP_OUTLINE
                color = ft.Colors.GREY
                if 'GET' in str(pkt.get('type_pdu', '')).upper():
                    icon = ft.Icons.GET_APP
                    color = ft.Colors.GREEN
                elif 'SET' in str(pkt.get('type_pdu', '')).upper():
                    icon = ft.Icons.SEND
                    color = ft.Colors.ORANGE
                elif 'TRAP' in str(pkt.get('type_pdu', '')).upper():
                    icon = ft.Icons.WARNING
                    color = ft.Colors.RED
                elif 'RESPONSE' in str(pkt.get('type_pdu', '')).upper():
                    icon = ft.Icons.TRY_SMS_STAR_ROUNDED
                    color = ft.Colors.PINK_700
                elif 'REPORT' in str(pkt.get('type_pdu', '')).upper():
                    icon = ft.Icons.CONNECT_WITHOUT_CONTACT
                    color = ft.Colors.PURPLE

                # Détection d'alerte sécurité
                alerte = pkt.get('contenu', {}).get('alerte_securite')
                titre_pdu = pkt.get('type_pdu', 'Unknown')
                if alerte:
                    niveau = alerte.get('niveau', '')
                    icon = ft.Icons.SHIELD
                    if niveau == 'CRITIQUE':
                        color = ft.Colors.RED_900
                    elif niveau == 'ELEVEE':
                        color = ft.Colors.DEEP_ORANGE
                    else:
                        color = ft.Colors.AMBER_700
                    titre_pdu = f"{niveau} - {titre_pdu}"

                recent_rows.append(
                    ft.ListTile(
                        leading=ft.CircleAvatar(content=ft.Icon(icon, color=ft.Colors.WHITE), bgcolor=color),
                        title=ft.Text(titre_pdu),
                        subtitle=ft.Text(f"[{pkt.get('version_snmp', '?')}] {pkt.get('adresse_source')} → {pkt.get('oid_racine', 'N/A')}"),
                        trailing=ft.Text(str(pkt.get('timestamp_reception'))[11:19], color=ft.Colors.GREY_500)
                    )
                )
            
            if not recent_rows:
                recent_rows.append(ft.Text("Aucune activité récente", italic=True, color=ft.Colors.GREY))

            # Cartes statistiques (Même structure mais avec self.stats dynamique)
            stats_cards = ft.Row([
                ft.Card(
                    content=ft.Container(
                        content=ft.Column([
                            ft.Row([ft.Icon(ft.Icons.ANALYTICS, size=35, color=ft.Colors.BLUE), 
                                   ft.Text(str(self.stats["total_requests"]), size=26, weight=ft.FontWeight.BOLD)], 
                                   alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
                            ft.Text("Total Paquets", size=14, color=ft.Colors.GREY_600),
                        ]), padding=20, width=220
                    ), elevation=2
                ),
                ft.Card(
                    content=ft.Container(
                        content=ft.Column([
                            ft.Row([ft.Icon(ft.Icons.GET_APP, size=35, color=ft.Colors.GREEN), 
                                   ft.Text(str(self.stats["get_requests"]), size=26, weight=ft.FontWeight.BOLD)], 
                                   alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
                            ft.Text("GET Requests", size=14, color=ft.Colors.GREY_600),
                        ]), padding=20, width=220
                    ), elevation=2
                ),
                ft.Card(
                    content=ft.Container(
                        content=ft.Column([
                            ft.Row([ft.Icon(ft.Icons.SEND, size=35, color=ft.Colors.ORANGE), 
                                   ft.Text(str(self.stats["set_requests"]), size=26, weight=ft.FontWeight.BOLD)], 
                                   alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
                            ft.Text("SET Requests", size=14, color=ft.Colors.GREY_600),
                        ]), padding=20, width=220
                    ), elevation=2
                ),
                ft.Card(
                    content=ft.Container(
                        content=ft.Column([
                            ft.Row([ft.Icon(ft.Icons.TRY_SMS_STAR_ROUNDED, size=35, color=ft.Colors.PINK_700),
                                   ft.Text(str(self.stats["response_requests"]), size=26, weight=ft.FontWeight.BOLD)],
                                   alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
                            ft.Text("Responses", size=14, color=ft.Colors.GREY_600),
                        ]), padding=20, width=220
                    ), elevation=2
                ),
                ft.Card(
                    content=ft.Container(
                        content=ft.Column([
                            ft.Row([ft.Icon(ft.Icons.CONNECT_WITHOUT_CONTACT, size=35, color=ft.Colors.PURPLE),
                                   ft.Text(str(self.stats["report_requests"]), size=26, weight=ft.FontWeight.BOLD)],
                                   alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
                            ft.Text("Reports SNMPv3", size=14, color=ft.Colors.GREY_600),
                        ]), padding=20, width=220
                    ), elevation=2
                ),
                ft.Card(
                    content=ft.Container(
                        content=ft.Column([
                            ft.Row([ft.Icon(ft.Icons.ERROR_OUTLINE, size=35, color=ft.Colors.AMBER_700),
                                   ft.Text(str(self.stats["errors"]), size=26, weight=ft.FontWeight.BOLD)],
                                   alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
                            ft.Text("Erreurs SNMP", size=14, color=ft.Colors.GREY_600),
                        ]), padding=20, width=220
                    ), elevation=2
                ),
                ft.Card(
                    content=ft.Container(
                        content=ft.Column([
                            ft.Row([ft.Icon(ft.Icons.SHIELD, size=35, color=ft.Colors.RED),
                                   ft.Text(str(self.stats["anomalies"]), size=26, weight=ft.FontWeight.BOLD)],
                                   alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
                            ft.Text("Alertes Sécurité", size=14, color=ft.Colors.GREY_600),
                        ]), padding=20, width=220
                    ), elevation=2
                ),
            ], alignment=ft.MainAxisAlignment.SPACE_AROUND, wrap=True)
            
            recent_activity = ft.Card(
                content=ft.Container(
                    content=ft.Column([
                        ft.Row([
                            ft.Text("Activité Récente (BDD)", size=18, weight=ft.FontWeight.BOLD),
                            ft.IconButton(icon=ft.Icons.REFRESH, on_click=update_dashboard_view)
                        ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
                        ft.Divider(),
                        ft.Column(recent_rows)
                    ]), padding=20
                ), elevation=2
            )
            
            return ft.Column([
                ft.Text(f"Bienvenue, {self.current_user}", size=28, weight=ft.FontWeight.BOLD),
                ft.Text(f"Données synchronisées à {self.stats['last_update']}", size=16, color=ft.Colors.GREY_600),
                ft.Container(height=20),
                stats_cards,
                ft.Container(height=20),
                recent_activity
            ], expand=True, scroll=ft.ScrollMode.AUTO)
        
        # --- PAGE TRAFFIC CONNECTÉE BDD ---
        def create_traffic_page():
            PAGE_SIZE = 100
            current_offset = [0]

            traffic_table_ref = ft.Ref[ft.DataTable]()
            page_label_ref = ft.Ref[ft.Text]()
            btn_prev_ref = ft.Ref[ft.ElevatedButton]()
            btn_next_ref = ft.Ref[ft.ElevatedButton]()

            niveau_colors = {
                'SUSPECT': ft.Colors.AMBER_700,
                'ELEVEE': ft.Colors.DEEP_ORANGE,
                'CRITIQUE': ft.Colors.RED_900,
            }

            def build_where(ip_source=None, pdu_type=None, version=None, oid=None):
                clauses = ["1=1"]
                params = []
                if ip_source and ip_source.strip():
                    clauses.append("adresse_source = ?")
                    params.append(ip_source.strip())
                if pdu_type and pdu_type != "Tous":
                    clauses.append("UPPER(type_pdu) LIKE ?")
                    params.append(f"%{pdu_type.upper()}%")
                if version and version != "Toutes":
                    clauses.append("version_snmp = ?")
                    params.append(version)
                if oid and oid.strip():
                    clauses.append("oid_racine LIKE ?")
                    params.append(f"%{oid.strip()}%")
                return " AND ".join(clauses), params

            def get_total(ip_source=None, pdu_type=None, version=None, oid=None):
                if not self.db:
                    return 0
                try:
                    cursor = self.db.connection.cursor()
                    where, params = build_where(ip_source, pdu_type, version, oid)
                    cursor.execute(f"SELECT COUNT(*) FROM paquets_recus WHERE {where}", params)
                    return cursor.fetchone()[0]
                except Exception as e:
                    print(f"Erreur count traffic: {e}")
                    return 0

            def load_page(offset, ip_source=None, pdu_type=None, version=None, oid=None):
                rows = []
                if not self.db:
                    return rows
                try:
                    cursor = self.db.connection.cursor()
                    where, params = build_where(ip_source, pdu_type, version, oid)
                    cursor.execute(
                        f"SELECT * FROM paquets_recus WHERE {where} "
                        f"ORDER BY timestamp_reception DESC LIMIT ? OFFSET ?",
                        params + [PAGE_SIZE, offset]
                    )
                    for row in cursor.fetchall():
                        p = dict(row)
                        t_pdu = str(p.get('type_pdu', 'Unknown'))

                        # Détermination status/couleur avec détection d'anomalie
                        status = "OK"
                        status_color = ft.Colors.GREEN

                        try:
                            contenu = json.loads(p.get('contenu_json', '{}'))
                        except Exception:
                            contenu = {}
                        alerte = contenu.get('alerte_securite')

                        if alerte:
                            niveau = alerte.get('niveau', '?')
                            status = niveau
                            status_color = niveau_colors.get(niveau, ft.Colors.GREY)
                        elif str(p.get('error_status', '0')) != '0':
                            status = f"Err {p.get('error_status')}"
                            status_color = ft.Colors.RED
                        elif 'Trap' in t_pdu:
                            status = "Trap"
                            status_color = ft.Colors.BLUE

                        rows.append(ft.DataRow(cells=[
                            ft.DataCell(ft.Text(str(p.get('timestamp_reception', ''))[11:19], size=12)),
                            ft.DataCell(ft.Text(p.get('adresse_source', ''), size=12, weight=ft.FontWeight.BOLD)),
                            ft.DataCell(ft.Container(
                                ft.Text(str(p.get('version_snmp', 'N/A')), color=ft.Colors.WHITE, size=11, weight=ft.FontWeight.BOLD),
                                bgcolor=ft.Colors.TEAL if str(p.get('version_snmp', '')).lower() == 'v3' else ft.Colors.BLUE_GREY,
                                padding=ft.padding.symmetric(horizontal=8, vertical=4),
                                border_radius=4,
                            )),
                            ft.DataCell(ft.Container(
                                ft.Text(t_pdu[:15], color=ft.Colors.WHITE, size=11, weight=ft.FontWeight.BOLD),
                                bgcolor=ft.Colors.BLUE_700,
                                padding=ft.padding.symmetric(horizontal=8, vertical=4),
                                border_radius=4,
                            )),
                            ft.DataCell(ft.Text(str(p.get('oid_racine', 'N/A'))[:25] + "...", size=11, color=ft.Colors.GREY_700)),
                            ft.DataCell(ft.Container(
                                ft.Text(status, color=ft.Colors.WHITE, size=11, weight=ft.FontWeight.BOLD),
                                bgcolor=status_color,
                                padding=ft.padding.symmetric(horizontal=8, vertical=4),
                                border_radius=4,
                            )),
                        ]))
                except Exception as e:
                    print(f"Erreur chargement traffic: {e}")
                return rows

            def update_view():
                ip = ip_filter.value
                typ = type_filter.value
                ver = version_filter.value
                oid_val = oid_filter.value
                total = get_total(ip, typ, ver, oid_val)
                rows = load_page(current_offset[0], ip, typ, ver, oid_val)
                page_num = (current_offset[0] // PAGE_SIZE) + 1
                total_pages = max(1, (total + PAGE_SIZE - 1) // PAGE_SIZE)

                if traffic_table_ref.current:
                    traffic_table_ref.current.rows = rows
                if page_label_ref.current:
                    page_label_ref.current.value = f"Page {page_num} / {total_pages}  ({total} paquets)"
                if btn_prev_ref.current:
                    btn_prev_ref.current.disabled = current_offset[0] == 0
                if btn_next_ref.current:
                    btn_next_ref.current.disabled = current_offset[0] + PAGE_SIZE >= total
                page.update()

            def on_prev(e):
                current_offset[0] = max(0, current_offset[0] - PAGE_SIZE)
                update_view()

            def on_next(e):
                current_offset[0] += PAGE_SIZE
                update_view()

            def on_filter(e=None):
                current_offset[0] = 0
                update_view()

            def on_refresh(e):
                update_view()

            # Filtres UI
            ip_filter = ft.TextField(
                hint_text="Filtrer par IP source...",
                prefix_icon=ft.Icons.SEARCH,
                width=200,
                on_submit=on_filter,
            )

            type_filter = ft.Dropdown(
                hint_text="Type de requête",
                options=[
                    ft.dropdown.Option("Tous"),
                    ft.dropdown.Option("GET"),
                    ft.dropdown.Option("SET"),
                    ft.dropdown.Option("TRAP"),
                    ft.dropdown.Option("RESPONSE"),
                    ft.dropdown.Option("REPORT"),
                ],
                width=150,
                on_change=on_filter,
            )

            version_filter = ft.Dropdown(
                hint_text="Version SNMP",
                options=[
                    ft.dropdown.Option("Toutes"),
                    ft.dropdown.Option("v2c"),
                    ft.dropdown.Option("v3"),
                ],
                width=140,
                on_change=on_filter,
            )

            oid_filter = ft.TextField(
                hint_text="Filtrer par OID...",
                prefix_icon=ft.Icons.ACCOUNT_TREE,
                width=220,
                on_submit=on_filter,
            )

            # Chargement initial
            initial_total = get_total()
            initial_rows = load_page(0)
            total_pages_init = max(1, (initial_total + PAGE_SIZE - 1) // PAGE_SIZE)

            traffic_table = ft.DataTable(
                ref=traffic_table_ref,
                columns=[
                    ft.DataColumn(ft.Text("Heure", weight=ft.FontWeight.BOLD)),
                    ft.DataColumn(ft.Text("Source", weight=ft.FontWeight.BOLD)),
                    ft.DataColumn(ft.Text("Version", weight=ft.FontWeight.BOLD)),
                    ft.DataColumn(ft.Text("Type", weight=ft.FontWeight.BOLD)),
                    ft.DataColumn(ft.Text("OID", weight=ft.FontWeight.BOLD)),
                    ft.DataColumn(ft.Text("Statut", weight=ft.FontWeight.BOLD)),
                ],
                rows=initial_rows,
            )

            pagination_row = ft.Row([
                ft.ElevatedButton("Précédent", icon=ft.Icons.ARROW_BACK, on_click=on_prev,
                                  disabled=True, ref=btn_prev_ref),
                ft.Text(f"Page 1 / {total_pages_init}  ({initial_total} paquets)",
                        size=14, weight=ft.FontWeight.BOLD, ref=page_label_ref),
                ft.ElevatedButton("Suivant", icon=ft.Icons.ARROW_FORWARD, on_click=on_next,
                                  disabled=initial_total <= PAGE_SIZE, ref=btn_next_ref),
            ], alignment=ft.MainAxisAlignment.CENTER, spacing=20)

            return ft.Column([
                ft.Row([
                    ft.Text("Traffic SNMP (BDD)", size=24, weight=ft.FontWeight.BOLD),
                    ft.IconButton(icon=ft.Icons.REFRESH, on_click=on_refresh),
                ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
                ft.Container(height=15),
                ft.Row([ip_filter, type_filter, version_filter, oid_filter, ft.ElevatedButton("Filtrer", on_click=on_filter)], spacing=15, wrap=True),
                ft.Container(height=15),
                ft.Card(
                    content=ft.Container(
                        content=ft.Column([
                            pagination_row,
                            ft.Container(height=10),
                            traffic_table,
                            ft.Container(height=10),
                            pagination_row,
                        ]), padding=15,
                    ), elevation=2,
                ),
            ], expand=True, scroll=ft.ScrollMode.AUTO)

        # --- AUTRES PAGES (Non connectées BDD pour l'instant mais conservées) ---
        def create_send_page():
            if not SNMP_SENDER_AVAILABLE or not PYSNMP_AVAILABLE:
                return ft.Column([
                    ft.Text("Emission de Trames SNMP", size=24, weight=ft.FontWeight.BOLD),
                    ft.Container(height=20),
                    ft.Card(content=ft.Container(content=ft.Column([
                        ft.Icon(ft.Icons.WARNING, size=50, color=ft.Colors.ORANGE),
                        ft.Text("Module pysnmp non disponible", size=18, weight=ft.FontWeight.BOLD),
                        ft.Text("Installez pysnmp : pip install pysnmp-lextudio", color=ft.Colors.GREY_600),
                    ], horizontal_alignment=ft.CrossAxisAlignment.CENTER), padding=30), elevation=2),
                ])

            # --- Champs du formulaire ---
            ip_field = ft.TextField(label="IP cible", hint_text="ex: 192.168.1.1", width=250, prefix_icon=ft.Icons.COMPUTER)
            port_field = ft.TextField(label="Port", value="161", width=100)

            version_dropdown = ft.Dropdown(
                label="Version SNMP", width=150, value="v2c",
                options=[ft.dropdown.Option("v2c"), ft.dropdown.Option("v3")],
            )
            pdu_dropdown = ft.Dropdown(
                label="Type PDU", width=150, value="GET",
                options=[ft.dropdown.Option("GET"), ft.dropdown.Option("GETNEXT"),
                         ft.dropdown.Option("SET"), ft.dropdown.Option("TRAP")],
            )

            # Auth v2c
            community_field = ft.TextField(label="Community string", value="public", width=250)
            v2c_container = ft.Container(content=ft.Row([community_field], spacing=15), visible=True)

            # Auth v3
            username_field = ft.TextField(label="Username", width=200)
            auth_pass_field = ft.TextField(label="Auth password", password=True, can_reveal_password=True, width=200)
            priv_pass_field = ft.TextField(label="Priv password", password=True, can_reveal_password=True, width=200)
            v3_container = ft.Container(
                content=ft.Row([username_field, auth_pass_field, priv_pass_field], spacing=15, wrap=True),
                visible=False,
            )

            # OID
            oid_field = ft.TextField(label="OID", hint_text="ex: 1.3.6.1.2.1.1.1.0", width=400, prefix_icon=ft.Icons.ACCOUNT_TREE)
            oid_container = ft.Container(content=oid_field, visible=True)

            # SET
            set_value_field = ft.TextField(label="Valeur", width=250)
            set_type_dropdown = ft.Dropdown(
                label="Type", width=130, value="String",
                options=[ft.dropdown.Option("String"), ft.dropdown.Option("Integer")],
            )
            set_container = ft.Container(content=ft.Row([set_value_field, set_type_dropdown], spacing=15), visible=False)

            # TRAP
            trap_oid_field = ft.TextField(label="Trap OID", hint_text="ex: 1.3.6.1.6.3.1.1.5.4", width=350)
            trap_vb_oid_field = ft.TextField(label="VarBind OID (optionnel)", width=300)
            trap_vb_value_field = ft.TextField(label="VarBind valeur (optionnel)", width=200)
            trap_container = ft.Container(
                content=ft.Column([
                    trap_oid_field,
                    ft.Row([trap_vb_oid_field, trap_vb_value_field], spacing=15),
                ]),
                visible=False,
            )

            # Resultat
            result_badge = ft.Container(visible=False)
            result_time = ft.Text("", size=13, color=ft.Colors.GREY_600, visible=False)
            result_varbinds = ft.Column([], spacing=5)
            result_error = ft.Text("", size=13, color=ft.Colors.RED, visible=False)
            result_container = ft.Card(
                content=ft.Container(
                    content=ft.Column([
                        ft.Text("Resultat", size=16, weight=ft.FontWeight.BOLD),
                        ft.Divider(),
                        result_badge, result_time, result_varbinds, result_error,
                    ]),
                    padding=15,
                ),
                elevation=2, visible=False,
            )

            # Bouton + spinner
            send_spinner = ft.ProgressRing(width=20, height=20, stroke_width=3, visible=False)
            send_button = ft.ElevatedButton(
                text="Envoyer", icon=ft.Icons.SEND, width=200, height=45,
                style=ft.ButtonStyle(color=ft.Colors.WHITE, bgcolor=ft.Colors.BLUE_700),
            )

            def on_version_change(e):
                is_v2c = version_dropdown.value == "v2c"
                v2c_container.visible = is_v2c
                v3_container.visible = not is_v2c
                page.update()

            def on_pdu_change(e):
                pdu = pdu_dropdown.value
                oid_container.visible = pdu != "TRAP"
                set_container.visible = pdu == "SET"
                trap_container.visible = pdu == "TRAP"
                if pdu == "TRAP":
                    port_field.value = "162"
                else:
                    if port_field.value == "162":
                        port_field.value = "161"
                page.update()

            version_dropdown.on_change = on_version_change
            pdu_dropdown.on_change = on_pdu_change

            def fill_oid(oid_value):
                def handler(e):
                    oid_field.value = oid_value
                    page.update()
                return handler

            preset_buttons = ft.Row([
                ft.OutlinedButton("sysDescr", on_click=fill_oid("1.3.6.1.2.1.1.1.0")),
                ft.OutlinedButton("sysUpTime", on_click=fill_oid("1.3.6.1.2.1.1.3.0")),
                ft.OutlinedButton("sysName", on_click=fill_oid("1.3.6.1.2.1.1.5.0")),
                ft.OutlinedButton("sysLocation", on_click=fill_oid("1.3.6.1.2.1.1.6.0")),
                ft.OutlinedButton("ifDescr", on_click=fill_oid("1.3.6.1.2.1.2.2.1.2")),
            ], wrap=True, spacing=8)

            async def do_send(e):
                # Validation
                if not ip_field.value or not ip_field.value.strip():
                    self.show_snackbar(page, "Veuillez renseigner l'IP cible", ft.Colors.RED)
                    return

                pdu = pdu_dropdown.value
                if pdu != "TRAP" and (not oid_field.value or not oid_field.value.strip()):
                    self.show_snackbar(page, "Veuillez renseigner l'OID", ft.Colors.RED)
                    return
                if pdu == "TRAP" and (not trap_oid_field.value or not trap_oid_field.value.strip()):
                    self.show_snackbar(page, "Veuillez renseigner le Trap OID", ft.Colors.RED)
                    return
                if pdu == "SET" and not set_value_field.value:
                    self.show_snackbar(page, "Veuillez renseigner la valeur SET", ft.Colors.RED)
                    return

                # UI : envoi en cours
                send_button.disabled = True
                send_spinner.visible = True
                result_container.visible = False
                page.update()

                try:
                    host = ip_field.value.strip()
                    port = int(port_field.value or "161")
                    ver = version_dropdown.value
                    comm = community_field.value or "public"
                    user = username_field.value or ""
                    auth_p = auth_pass_field.value or ""
                    priv_p = priv_pass_field.value or ""

                    result: SNMPResult
                    if pdu == "GET":
                        result = await send_get(host, port, oid_field.value.strip(), ver, comm, user, auth_p, priv_p)
                    elif pdu == "GETNEXT":
                        result = await send_getnext(host, port, oid_field.value.strip(), ver, comm, user, auth_p, priv_p)
                    elif pdu == "SET":
                        vtype = "integer" if set_type_dropdown.value == "Integer" else "string"
                        result = await send_set(host, port, oid_field.value.strip(), set_value_field.value, vtype, ver, comm, user, auth_p, priv_p)
                    else:  # TRAP
                        result = await send_trap(
                            host, port, trap_oid_field.value.strip(),
                            trap_vb_oid_field.value or "", trap_vb_value_field.value or "",
                            ver, comm, user, auth_p, priv_p,
                        )

                    # Afficher le resultat
                    if result.success:
                        result_badge.content = ft.Container(
                            ft.Text("SUCCES", color=ft.Colors.WHITE, size=14, weight=ft.FontWeight.BOLD),
                            bgcolor=ft.Colors.GREEN, padding=ft.padding.symmetric(horizontal=15, vertical=6), border_radius=5,
                        )
                    else:
                        result_badge.content = ft.Container(
                            ft.Text("ECHEC", color=ft.Colors.WHITE, size=14, weight=ft.FontWeight.BOLD),
                            bgcolor=ft.Colors.RED, padding=ft.padding.symmetric(horizontal=15, vertical=6), border_radius=5,
                        )
                    result_badge.visible = True

                    result_time.value = f"Temps : {result.elapsed_ms:.1f} ms"
                    result_time.visible = True

                    result_varbinds.controls.clear()
                    for oid_str, val_str in result.varbinds:
                        result_varbinds.controls.append(
                            ft.Row([
                                ft.Text(oid_str, size=12, weight=ft.FontWeight.BOLD, color=ft.Colors.BLUE_700),
                                ft.Text("=", size=12),
                                ft.Text(val_str, size=12, selectable=True),
                            ], spacing=8)
                        )

                    if result.error_message:
                        result_error.value = f"Erreur : {result.error_message}"
                        result_error.visible = True
                    else:
                        result_error.visible = False

                    result_container.visible = True

                except Exception as exc:
                    result_badge.content = ft.Container(
                        ft.Text("ERREUR", color=ft.Colors.WHITE, size=14, weight=ft.FontWeight.BOLD),
                        bgcolor=ft.Colors.RED, padding=ft.padding.symmetric(horizontal=15, vertical=6), border_radius=5,
                    )
                    result_badge.visible = True
                    result_error.value = f"Exception : {exc}"
                    result_error.visible = True
                    result_time.visible = False
                    result_varbinds.controls.clear()
                    result_container.visible = True
                finally:
                    send_button.disabled = False
                    send_spinner.visible = False
                    page.update()

            send_button.on_click = do_send

            return ft.Column([
                ft.Text("Emission de Trames SNMP", size=24, weight=ft.FontWeight.BOLD),
                ft.Text("Envoi direct de requetes SNMP v2c / v3", size=14, color=ft.Colors.GREY_600),
                ft.Container(height=15),
                ft.Card(content=ft.Container(content=ft.Column([
                    ft.Text("Cible et protocole", size=16, weight=ft.FontWeight.BOLD),
                    ft.Divider(),
                    ft.Row([ip_field, port_field, version_dropdown, pdu_dropdown], spacing=15, wrap=True),
                    ft.Container(height=10),
                    ft.Text("Authentification", size=14, weight=ft.FontWeight.BOLD, color=ft.Colors.GREY_700),
                    v2c_container,
                    v3_container,
                ]), padding=15), elevation=2),
                ft.Container(height=10),
                ft.Card(content=ft.Container(content=ft.Column([
                    ft.Text("Parametres de la requete", size=16, weight=ft.FontWeight.BOLD),
                    ft.Divider(),
                    oid_container,
                    set_container,
                    trap_container,
                    ft.Container(height=8),
                    ft.Text("OIDs rapides", size=13, color=ft.Colors.GREY_700),
                    preset_buttons,
                ]), padding=15), elevation=2),
                ft.Container(height=15),
                ft.Row([send_button, send_spinner], spacing=15, alignment=ft.MainAxisAlignment.CENTER),
                ft.Container(height=15),
                result_container,
            ], expand=True, scroll=ft.ScrollMode.AUTO)

        def create_anomalies_page():
            PAGE_SIZE = 100
            current_offset = [0]  # liste pour mutabilité dans les closures

            anomalies_table_ref = ft.Ref[ft.DataTable]()
            count_suspect_ref = ft.Ref[ft.Text]()
            count_elevee_ref = ft.Ref[ft.Text]()
            count_critique_ref = ft.Ref[ft.Text]()
            page_label_ref = ft.Ref[ft.Text]()
            btn_prev_ref = ft.Ref[ft.ElevatedButton]()
            btn_next_ref = ft.Ref[ft.ElevatedButton]()

            niveau_colors = {
                'SUSPECT': ft.Colors.AMBER_700,
                'ELEVEE': ft.Colors.DEEP_ORANGE,
                'CRITIQUE': ft.Colors.RED_900,
            }

            def get_counts(niveau_filtre=None):
                """Récupère les compteurs globaux (indépendant de la page)"""
                counts = {'SUSPECT': 0, 'ELEVEE': 0, 'CRITIQUE': 0, 'total_filtre': 0}
                if not self.db:
                    return counts
                try:
                    cursor = self.db.connection.cursor()
                    for niv in ('SUSPECT', 'ELEVEE', 'CRITIQUE'):
                        cursor.execute(
                            "SELECT COUNT(*) FROM paquets_recus "
                            "WHERE contenu_json LIKE '%alerte_securite%' "
                            "AND contenu_json LIKE ?",
                            (f'%"niveau": "{niv}"%',)
                        )
                        counts[niv] = cursor.fetchone()[0]
                    if niveau_filtre and niveau_filtre != "Tous":
                        counts['total_filtre'] = counts.get(niveau_filtre, 0)
                    else:
                        counts['total_filtre'] = counts['SUSPECT'] + counts['ELEVEE'] + counts['CRITIQUE']
                except Exception as e:
                    print(f"Erreur compteurs anomalies: {e}")
                return counts

            def load_page(offset, niveau_filtre=None):
                """Charge une page de 100 alertes depuis la BDD"""
                rows = []
                if not self.db:
                    return rows
                try:
                    cursor = self.db.connection.cursor()
                    if niveau_filtre and niveau_filtre != "Tous":
                        cursor.execute(
                            "SELECT * FROM paquets_recus "
                            "WHERE contenu_json LIKE '%alerte_securite%' "
                            "AND contenu_json LIKE ? "
                            "ORDER BY timestamp_reception DESC LIMIT ? OFFSET ?",
                            (f'%"niveau": "{niveau_filtre}"%', PAGE_SIZE, offset)
                        )
                    else:
                        cursor.execute(
                            "SELECT * FROM paquets_recus "
                            "WHERE contenu_json LIKE '%alerte_securite%' "
                            "ORDER BY timestamp_reception DESC LIMIT ? OFFSET ?",
                            (PAGE_SIZE, offset)
                        )
                    for row in cursor.fetchall():
                        p = dict(row)
                        try:
                            contenu = json.loads(p.get('contenu_json', '{}'))
                        except Exception:
                            contenu = {}
                        alerte = contenu.get('alerte_securite', {})
                        niveau = alerte.get('niveau', '?')
                        badge_color = niveau_colors.get(niveau, ft.Colors.GREY)

                        rows.append(ft.DataRow(cells=[
                            ft.DataCell(ft.Text(str(p.get('timestamp_reception', ''))[11:19], size=12)),
                            ft.DataCell(ft.Text(p.get('adresse_source', ''), size=12, weight=ft.FontWeight.BOLD)),
                            ft.DataCell(ft.Container(
                                ft.Text(p.get('type_pdu', '?'), color=ft.Colors.WHITE, size=11, weight=ft.FontWeight.BOLD),
                                bgcolor=ft.Colors.BLUE_700,
                                padding=ft.padding.symmetric(horizontal=8, vertical=4),
                                border_radius=4,
                            )),
                            ft.DataCell(ft.Container(
                                ft.Text(niveau, color=ft.Colors.WHITE, size=11, weight=ft.FontWeight.BOLD),
                                bgcolor=badge_color,
                                padding=ft.padding.symmetric(horizontal=8, vertical=4),
                                border_radius=4,
                            )),
                            ft.DataCell(ft.Text(alerte.get('message', ''), size=11)),
                            ft.DataCell(ft.Text(alerte.get('action_requise', ''), size=11, color=ft.Colors.GREY_700)),
                        ]))
                except Exception as e:
                    print(f"Erreur chargement anomalies: {e}")
                return rows

            def update_view():
                filtre = niveau_filter.value
                counts = get_counts(filtre)
                rows = load_page(current_offset[0], filtre)
                total = counts['total_filtre']
                page_num = (current_offset[0] // PAGE_SIZE) + 1
                total_pages = max(1, (total + PAGE_SIZE - 1) // PAGE_SIZE)

                if anomalies_table_ref.current:
                    anomalies_table_ref.current.rows = rows
                if count_suspect_ref.current:
                    count_suspect_ref.current.value = str(counts['SUSPECT'])
                if count_elevee_ref.current:
                    count_elevee_ref.current.value = str(counts['ELEVEE'])
                if count_critique_ref.current:
                    count_critique_ref.current.value = str(counts['CRITIQUE'])
                if page_label_ref.current:
                    page_label_ref.current.value = f"Page {page_num} / {total_pages}  ({total} alertes)"
                if btn_prev_ref.current:
                    btn_prev_ref.current.disabled = current_offset[0] == 0
                if btn_next_ref.current:
                    btn_next_ref.current.disabled = current_offset[0] + PAGE_SIZE >= total
                page.update()

            def on_prev(e):
                current_offset[0] = max(0, current_offset[0] - PAGE_SIZE)
                update_view()

            def on_next(e):
                current_offset[0] += PAGE_SIZE
                update_view()

            def on_filter_change(e):
                current_offset[0] = 0
                update_view()

            def on_refresh(e):
                update_view()

            niveau_filter = ft.Dropdown(
                hint_text="Filtrer par niveau",
                options=[
                    ft.dropdown.Option("Tous"),
                    ft.dropdown.Option("SUSPECT"),
                    ft.dropdown.Option("ELEVEE"),
                    ft.dropdown.Option("CRITIQUE"),
                ],
                width=180,
                on_change=on_filter_change,
            )

            # Chargement initial
            initial_counts = get_counts()
            initial_rows = load_page(0)
            total_init = initial_counts['total_filtre']
            total_pages_init = max(1, (total_init + PAGE_SIZE - 1) // PAGE_SIZE)

            summary_cards = ft.Row([
                ft.Card(content=ft.Container(content=ft.Column([
                    ft.Row([ft.Icon(ft.Icons.SHIELD, size=30, color=ft.Colors.AMBER_700),
                            ft.Text(str(initial_counts['SUSPECT']), size=22, weight=ft.FontWeight.BOLD, ref=count_suspect_ref)],
                           alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
                    ft.Text("Suspect", size=13, color=ft.Colors.GREY_600),
                ]), padding=15, width=170), elevation=2),
                ft.Card(content=ft.Container(content=ft.Column([
                    ft.Row([ft.Icon(ft.Icons.SHIELD, size=30, color=ft.Colors.DEEP_ORANGE),
                            ft.Text(str(initial_counts['ELEVEE']), size=22, weight=ft.FontWeight.BOLD, ref=count_elevee_ref)],
                           alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
                    ft.Text("Élevée", size=13, color=ft.Colors.GREY_600),
                ]), padding=15, width=170), elevation=2),
                ft.Card(content=ft.Container(content=ft.Column([
                    ft.Row([ft.Icon(ft.Icons.SHIELD, size=30, color=ft.Colors.RED_900),
                            ft.Text(str(initial_counts['CRITIQUE']), size=22, weight=ft.FontWeight.BOLD, ref=count_critique_ref)],
                           alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
                    ft.Text("Critique", size=13, color=ft.Colors.GREY_600),
                ]), padding=15, width=170), elevation=2),
            ], spacing=15)

            anomalies_table = ft.DataTable(
                ref=anomalies_table_ref,
                columns=[
                    ft.DataColumn(ft.Text("Heure", weight=ft.FontWeight.BOLD)),
                    ft.DataColumn(ft.Text("Source", weight=ft.FontWeight.BOLD)),
                    ft.DataColumn(ft.Text("Type PDU", weight=ft.FontWeight.BOLD)),
                    ft.DataColumn(ft.Text("Niveau", weight=ft.FontWeight.BOLD)),
                    ft.DataColumn(ft.Text("Message", weight=ft.FontWeight.BOLD)),
                    ft.DataColumn(ft.Text("Action", weight=ft.FontWeight.BOLD)),
                ],
                rows=initial_rows,
            )

            pagination_row = ft.Row([
                ft.ElevatedButton("Précédent", icon=ft.Icons.ARROW_BACK, on_click=on_prev,
                                  disabled=True, ref=btn_prev_ref),
                ft.Text(f"Page 1 / {total_pages_init}  ({total_init} alertes)",
                        size=14, weight=ft.FontWeight.BOLD, ref=page_label_ref),
                ft.ElevatedButton("Suivant", icon=ft.Icons.ARROW_FORWARD, on_click=on_next,
                                  disabled=total_init <= PAGE_SIZE, ref=btn_next_ref),
            ], alignment=ft.MainAxisAlignment.CENTER, spacing=20)

            return ft.Column([
                ft.Row([
                    ft.Text("Détection d'Anomalies", size=24, weight=ft.FontWeight.BOLD),
                    ft.IconButton(icon=ft.Icons.REFRESH, on_click=on_refresh),
                ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
                ft.Text("Alertes de sécurité détectées par le collecteur SNMP", size=14, color=ft.Colors.GREY_600),
                ft.Container(height=15),
                summary_cards,
                ft.Container(height=15),
                ft.Row([niveau_filter], spacing=15),
                ft.Container(height=15),
                ft.Card(
                    content=ft.Container(
                        content=ft.Column([
                            pagination_row,
                            ft.Container(height=10),
                            anomalies_table,
                            ft.Container(height=10),
                            pagination_row,
                        ]), padding=15,
                    ), elevation=2,
                ),
            ], expand=True, scroll=ft.ScrollMode.AUTO)

        def create_stats_page():
            def refresh_stats(e=None):
                main_content.content = create_stats_page()
                page.update()
                self.show_snackbar(page, "Statistiques actualisées", ft.Colors.GREEN)

            data = self.get_stats_data()

            pdu_colors = [
                ft.Colors.GREEN, ft.Colors.ORANGE, ft.Colors.PINK_700,
                ft.Colors.RED, ft.Colors.PURPLE, ft.Colors.AMBER,
                ft.Colors.CYAN, ft.Colors.LIME,
            ]
            version_colors = {"v3": ft.Colors.TEAL, "v2c": ft.Colors.BLUE_GREY}

            # --- PieChart : Types PDU ---
            total_pdu = sum(r[1] for r in data["pdu_types"]) or 1
            pdu_sections = []
            pdu_legend_items = []
            for i, r in enumerate(data["pdu_types"]):
                pct = r[1] / total_pdu * 100
                color = pdu_colors[i % len(pdu_colors)]
                pdu_sections.append(ft.PieChartSection(
                    value=r[1], title="", color=color, radius=110,
                ))
                pdu_legend_items.append(ft.Row([
                    ft.Container(width=14, height=14, bgcolor=color, border_radius=3),
                    ft.Text(f"{r[0]}", size=12, weight=ft.FontWeight.W_500),
                    ft.Text(f"({r[1]} - {pct:.1f}%)", size=11, color=ft.Colors.GREY_600),
                ], spacing=8))
            if not pdu_sections:
                pdu_sections.append(ft.PieChartSection(
                    value=1, title="", color=ft.Colors.GREY, radius=110
                ))
                pdu_legend_items.append(ft.Text("Aucune donnée", italic=True, color=ft.Colors.GREY))
            pie_pdu = ft.Row([
                ft.Container(
                    content=ft.PieChart(sections=pdu_sections, sections_space=2, center_space_radius=0, expand=True),
                    expand=2,
                ),
                ft.Container(
                    content=ft.Column(pdu_legend_items, spacing=8, alignment=ft.MainAxisAlignment.CENTER),
                    expand=1, padding=ft.padding.only(left=10),
                ),
            ])

            # --- PieChart : Versions SNMP ---
            total_ver = sum(r[1] for r in data["versions"]) or 1
            ver_sections = []
            for r in data["versions"]:
                pct = r[1] / total_ver * 100
                c = version_colors.get(str(r[0]).lower(), ft.Colors.GREY)
                ver_sections.append(ft.PieChartSection(
                    value=r[1],
                    title=f"{r[0]}\n{pct:.1f}%",
                    color=c,
                    radius=110,
                    title_style=ft.TextStyle(
                        size=12, color=ft.Colors.WHITE,
                        weight=ft.FontWeight.BOLD,
                    ),
                    title_position=0.6,
                ))
            if not ver_sections:
                ver_sections.append(ft.PieChartSection(
                    value=1, title="Aucune donnée", color=ft.Colors.GREY, radius=110
                ))
            pie_ver = ft.PieChart(
                sections=ver_sections, sections_space=2,
                center_space_radius=0, expand=True,
            )

            # --- BarChart : Top 10 IPs ---
            bar_groups = []
            bar_labels = []
            max_bar = max((r[1] for r in data["top_ips"]), default=0)
            bar_palette = [
                ft.Colors.BLUE_700, ft.Colors.BLUE_500, ft.Colors.BLUE_400,
                ft.Colors.INDIGO_400, ft.Colors.INDIGO_300, ft.Colors.CYAN_600,
                ft.Colors.CYAN_400, ft.Colors.TEAL_400, ft.Colors.TEAL_300,
                ft.Colors.LIGHT_BLUE_400,
            ]
            for i, r in enumerate(data["top_ips"]):
                bar_groups.append(ft.BarChartGroup(
                    x=i,
                    bar_rods=[ft.BarChartRod(
                        from_y=0, to_y=r[1], width=22,
                        color=bar_palette[i % len(bar_palette)],
                        tooltip=f"{r[0]}: {r[1]}",
                        border_radius=4,
                    )],
                ))
                ip_label = str(r[0])
                if len(ip_label) > 13:
                    ip_label = ".." + ip_label[-11:]
                bar_labels.append(ft.ChartAxisLabel(
                    value=i,
                    label=ft.Container(
                        ft.Text(ip_label, size=8),
                        padding=ft.padding.only(top=5),
                    ),
                ))
            if bar_groups:
                bar_chart = ft.BarChart(
                    bar_groups=bar_groups,
                    bottom_axis=ft.ChartAxis(labels=bar_labels, labels_size=40),
                    left_axis=ft.ChartAxis(labels_size=50),
                    tooltip_bgcolor=ft.Colors.GREY_800,
                    max_y=(max_bar * 1.15) if max_bar > 0 else 10,
                    expand=True,
                )
            else:
                bar_chart = ft.Container(
                    ft.Text("Aucune donnée", italic=True, color=ft.Colors.GREY),
                    alignment=ft.alignment.center, expand=True,
                )

            # --- LineChart : Trafic temporel (30 derniers jours) ---
            temporal = data["temporal"]
            line_points = []
            line_labels = []
            max_line = 0
            step = max(1, len(temporal) // 6)
            for i, r in enumerate(temporal):
                cnt = r[1]
                if cnt > max_line:
                    max_line = cnt
                line_points.append(ft.LineChartDataPoint(i, cnt))
                day_str = str(r[0])[-5:]  # MM-DD
                if i % step == 0 or i == len(temporal) - 1:
                    line_labels.append(ft.ChartAxisLabel(
                        value=i,
                        label=ft.Container(
                            ft.Text(day_str, size=8),
                            padding=ft.padding.only(top=5),
                        ),
                    ))
            if line_points:
                line_chart = ft.LineChart(
                    data_series=[ft.LineChartData(
                        data_points=line_points,
                        stroke_width=3,
                        color=ft.Colors.BLUE_700,
                        curved=True,
                        stroke_cap_round=True,
                    )],
                    bottom_axis=ft.ChartAxis(labels=line_labels, labels_size=40),
                    left_axis=ft.ChartAxis(labels_size=50),
                    tooltip_bgcolor=ft.Colors.GREY_800,
                    max_y=(max_line * 1.15) if max_line > 0 else 10,
                    max_x=max(len(temporal) - 1, 0),
                    min_x=0, min_y=0,
                    expand=True,
                )
            else:
                line_chart = ft.Container(
                    ft.Text("Aucune donnée temporelle", italic=True, color=ft.Colors.GREY),
                    alignment=ft.alignment.center, expand=True,
                )

            # --- BarChart : Top 10 OIDs ---
            oid_groups = []
            oid_labels = []
            max_oid = max((r[1] for r in data["top_oids"]), default=0)
            oid_palette = [
                ft.Colors.DEEP_PURPLE_700, ft.Colors.DEEP_PURPLE_500, ft.Colors.DEEP_PURPLE_400,
                ft.Colors.PURPLE_400, ft.Colors.PURPLE_300, ft.Colors.INDIGO_600,
                ft.Colors.INDIGO_400, ft.Colors.BLUE_ACCENT_400, ft.Colors.BLUE_ACCENT_200,
                ft.Colors.DEEP_PURPLE_200,
            ]
            for i, r in enumerate(data["top_oids"]):
                oid_groups.append(ft.BarChartGroup(
                    x=i,
                    bar_rods=[ft.BarChartRod(
                        from_y=0, to_y=r[1], width=22,
                        color=oid_palette[i % len(oid_palette)],
                        tooltip=f"{r[0]}: {r[1]}",
                        border_radius=4,
                    )],
                ))
                oid_label = str(r[0])
                if len(oid_label) > 18:
                    oid_label = ".." + oid_label[-16:]
                oid_labels.append(ft.ChartAxisLabel(
                    value=i,
                    label=ft.Container(
                        ft.Text(oid_label, size=7),
                        padding=ft.padding.only(top=5),
                    ),
                ))
            if oid_groups:
                oid_chart = ft.BarChart(
                    bar_groups=oid_groups,
                    bottom_axis=ft.ChartAxis(labels=oid_labels, labels_size=40),
                    left_axis=ft.ChartAxis(labels_size=50),
                    tooltip_bgcolor=ft.Colors.GREY_800,
                    max_y=(max_oid * 1.15) if max_oid > 0 else 10,
                    expand=True,
                )
            else:
                oid_chart = ft.Container(
                    ft.Text("Aucune donnée", italic=True, color=ft.Colors.GREY),
                    alignment=ft.alignment.center, expand=True,
                )

            def chart_card(title, icon, chart, height=280):
                return ft.Card(
                    content=ft.Container(
                        content=ft.Column([
                            ft.Row([
                                ft.Icon(icon, color=ft.Colors.BLUE_700),
                                ft.Text(title, size=15, weight=ft.FontWeight.BOLD),
                            ]),
                            ft.Divider(),
                            ft.Container(content=chart, height=height),
                        ]),
                        padding=15,
                    ),
                    elevation=2, expand=True,
                )

            return ft.Column([
                ft.Row([
                    ft.Text("Statistiques", size=24, weight=ft.FontWeight.BOLD),
                    ft.IconButton(icon=ft.Icons.REFRESH, on_click=refresh_stats),
                ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
                ft.Container(height=10),
                chart_card("Distribution par Type PDU", ft.Icons.PIE_CHART, pie_pdu, height=350),
                ft.Container(height=15),
                chart_card("Distribution par Version SNMP", ft.Icons.DONUT_LARGE, pie_ver),
                ft.Container(height=15),
                chart_card("Top 10 Sources IP", ft.Icons.BAR_CHART, bar_chart),
                ft.Container(height=15),
                chart_card("Trafic (30 derniers jours)", ft.Icons.SHOW_CHART, line_chart),
                ft.Container(height=15),
                chart_card("Top 10 OIDs les plus requêtés", ft.Icons.ACCOUNT_TREE, oid_chart),
            ], expand=True, scroll=ft.ScrollMode.AUTO)

        # Gestion Navigation
        def on_navigation_change(e):
            selected_index = e.control.selected_index
            if selected_index == 0:
                main_content.content = create_dashboard()
            elif selected_index == 1:
                main_content.content = create_traffic_page()
            elif selected_index == 2:
                main_content.content = create_send_page()
            elif selected_index == 3:
                main_content.content = create_anomalies_page()
            elif selected_index == 4:
                main_content.content = create_stats_page()
            page.update()
        
        self.on_navigation_change = on_navigation_change
        
        # Header
        def logout_click(e):
            self.current_user = None
            self.current_page = "login"
            page.go("/")
            self.show_snackbar(page, "Déconnexion réussie", ft.Colors.BLUE)
        
        def create_header():
            return ft.Container(
                content=ft.Row([
                    ft.Row([ft.Icon(ft.Icons.NETWORK_CHECK, color=ft.Colors.BLUE_700), 
                           ft.Text("SNMP Monitor", size=20, weight=ft.FontWeight.BOLD, color=ft.Colors.BLUE_700)]),
                    ft.Row([
                        ft.Text(f"👤 {self.current_user}" if self.current_user else "", size=14),
                        ft.IconButton(icon=ft.Icons.LOGOUT, tooltip="Déconnexion", icon_color=ft.Colors.RED, on_click=logout_click)
                        if self.current_user else ft.Container()
                    ])
                ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
                bgcolor=ft.Colors.WHITE, padding=ft.padding.symmetric(horizontal=25, vertical=15),
                border=ft.border.only(bottom=ft.border.BorderSide(1, ft.Colors.GREY_200))
            )
        
        main_content = ft.Container(content=create_dashboard(), expand=True, padding=25)
        
        # Routeur
        def route_change(route):
            page.views.clear()
            if route.route == "/" or not self.current_user:
                page.views.append(ft.View("/", [create_login_page()], padding=0))
            else:
                page.views.append(
                    ft.View(route.route, [
                        ft.Column([create_header(), ft.Row([create_navigation(), ft.VerticalDivider(width=1), main_content], expand=True)], expand=True, spacing=0)
                    ], padding=0)
                )
            page.update()
        
        page.on_route_change = route_change
        page.go("/")

if __name__ == "__main__":
    app = SNMPMonitorApp()
    ft.app(
        target=app.main,
        view=ft.WEB_BROWSER,
        host="0.0.0.0",
        port=12000,
        assets_dir="assets",
        
    )
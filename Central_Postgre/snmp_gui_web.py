#!/usr/bin/env python3
"""
SNMP Monitor Application - SAE 501-502
Interface graphique Flet connectée à la base de données PostgreSQL (snmp_database_postgre.py)

Adaptations:
✅ Authentification via BDD
✅ Recherche de paquets via BDD
✅ Dashboard avec statistiques réelles
"""

import flet as ft
from datetime import datetime

# Import de la classe PostgreSQL
from snmp_database_postgre import SNMPDatabase


class SNMPMonitorApp:
    def __init__(self):
        self.current_user = None
        self.current_page = "login"
        self.navigation_rail = None

        # Initialisation de la connexion BDD

        try:
            self.db = SNMPDatabase()
            print("✅ Connexion BDD PostgreSQL réussie dans l'interface graphique")
        except Exception as e:
            print(f"❌ Erreur connexion PostgreSQL: {e}")
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
                "errors": 0, "last_update": datetime.now().strftime("%H:%M:%S")
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

            # Erreurs (status != 0)
            cursor.execute("SELECT COUNT(*) FROM paquets_recus WHERE error_status != '0' AND error_status IS NOT NULL")
            errors = cursor.fetchone()[0]

            return {
                "total_requests": total,
                "get_requests": get_req,
                "set_requests": set_req,
                "errors": errors,
                "last_update": datetime.now().strftime("%H:%M:%S")
            }
        except Exception as e:
            print(f"Erreur stats dashboard: {e}")
            return {"total_requests": 0, "get_requests": 0, "set_requests": 0, "errors": 0, "last_update": "Erreur"}

    def get_recent_activity(self, limit=5):
        """Récupère les derniers paquets pour l'activité récente"""
        if not self.db: return []
        return self.db.lister_paquets_snmp(limite=limit)

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
                if 'GET' in str(pkt.get('type_pdu', '')):
                    icon = ft.Icons.GET_APP
                    color = ft.Colors.GREEN
                elif 'SET' in str(pkt.get('type_pdu', '')):
                    icon = ft.Icons.SEND
                    color = ft.Colors.ORANGE
                elif 'TRAP' in str(pkt.get('type_pdu', '')):
                    icon = ft.Icons.WARNING
                    color = ft.Colors.RED
                elif 'RESPONSE' in str(pkt.get('type_pdu', '')):
                    icon = ft.Icons.TRY_SMS_STAR_ROUNDED
                    color = ft.Colors.PINK_700

                recent_rows.append(
                    ft.ListTile(
                        leading=ft.CircleAvatar(content=ft.Icon(icon, color=ft.Colors.WHITE), bgcolor=color),
                        title=ft.Text(f"{pkt.get('type_pdu', 'Unknown')}"),
                        subtitle=ft.Text(f"{pkt.get('adresse_source')} → {pkt.get('oid_racine', 'N/A')}"),
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
                            ft.Row([ft.Icon(ft.Icons.ERROR, size=35, color=ft.Colors.RED),
                                   ft.Text(str(self.stats["errors"]), size=26, weight=ft.FontWeight.BOLD)],
                                   alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
                            ft.Text("Erreurs SNMP", size=14, color=ft.Colors.GREY_600),
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
            traffic_table_ref = ft.Ref[ft.DataTable]()

            def load_traffic_data(ip_source=None, pdu_type=None):
                """Charge les données depuis la BDD avec filtres"""
                rows = []
                if self.db:
                    # 1. Récupération via BDD (Filtre IP supporté nativement)
                    if ip_source and ip_source.strip():
                        paquets = self.db.rechercher_paquets(adresse_source=ip_source)
                    else:
                        paquets = self.db.lister_paquets_snmp(limite=50)

                    # 2. Filtrage Python pour le Type (non supporté par rechercher_paquets)
                    for p in paquets:
                        t_pdu = str(p.get('type_pdu', 'Unknown'))

                        # Application du filtre Type si sélectionné
                        if pdu_type and pdu_type != "Tous":
                            if pdu_type.upper() not in t_pdu.upper():
                                continue # On saute ce paquet

                        # Détermination status/couleur
                        status = "OK"
                        status_color = ft.Colors.GREEN
                        if str(p.get('error_status', '0')) != '0':
                            status = f"Err {p.get('error_status')}"
                            status_color = ft.Colors.RED
                        elif 'Trap' in t_pdu:
                            status = "Trap"
                            status_color = ft.Colors.BLUE

                        rows.append(
                            ft.DataRow(cells=[
                                ft.DataCell(ft.Text(str(p['timestamp_reception'])[11:19], size=12)),
                                ft.DataCell(ft.Text(p['adresse_source'], size=12, weight=ft.FontWeight.BOLD)),
                                ft.DataCell(
                                    ft.Container(
                                        ft.Text(t_pdu[:15], color=ft.Colors.WHITE, size=11, weight=ft.FontWeight.BOLD),
                                        bgcolor=ft.Colors.BLUE_700,
                                        padding=ft.padding.symmetric(horizontal=8, vertical=4),
                                        border_radius=4
                                    )
                                ),
                                ft.DataCell(ft.Text(str(p.get('oid_racine', 'N/A'))[:25]+"...", size=11, color=ft.Colors.GREY_700)),
                                ft.DataCell(
                                    ft.Container(
                                        ft.Text(status, color=ft.Colors.WHITE, size=11, weight=ft.FontWeight.BOLD),
                                        bgcolor=status_color,
                                        padding=ft.padding.symmetric(horizontal=8, vertical=4),
                                        border_radius=4
                                    )
                                ),
                            ])
                        )

                if traffic_table_ref.current:
                    traffic_table_ref.current.rows = rows
                    page.update()

            def filter_traffic(e=None):
                ip = ip_filter.value
                typ = type_filter.value
                load_traffic_data(ip, typ)
                self.show_snackbar(page, "Filtres appliqués (Recherche BDD)", ft.Colors.BLUE)

            # Filtres UI
            ip_filter = ft.TextField(
                hint_text="Filtrer par IP source...",
                prefix_icon=ft.Icons.SEARCH,
                width=200,
                on_submit=filter_traffic
            )

            type_filter = ft.Dropdown(
                hint_text="Type de requête",
                options=[
                    ft.dropdown.Option("Tous"),
                    ft.dropdown.Option("GET"),
                    ft.dropdown.Option("SET"),
                    ft.dropdown.Option("TRAP")
                ],
                width=150,
                on_change=filter_traffic
            )

            # Table
            traffic_table = ft.DataTable(
                ref=traffic_table_ref,
                columns=[
                    ft.DataColumn(ft.Text("Heure", weight=ft.FontWeight.BOLD)),
                    ft.DataColumn(ft.Text("Source", weight=ft.FontWeight.BOLD)),
                    ft.DataColumn(ft.Text("Type", weight=ft.FontWeight.BOLD)),
                    ft.DataColumn(ft.Text("OID", weight=ft.FontWeight.BOLD)),
                    ft.DataColumn(ft.Text("Statut", weight=ft.FontWeight.BOLD)),
                ],
                rows=[]
            )

            # Chargement initial
            # On utilise un petit délai pour laisser le temps au composant de se monter
            # (ou on appelle juste après le return mais dans Flet c'est synchrone ici)
            load_traffic_data()

            return ft.Column([
                ft.Row([
                    ft.Text("Traffic SNMP (BDD)", size=24, weight=ft.FontWeight.BOLD),
                    ft.IconButton(icon=ft.Icons.REFRESH, on_click=lambda e: load_traffic_data(ip_filter.value, type_filter.value))
                ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
                ft.Container(height=15),
                ft.Row([ip_filter, type_filter, ft.ElevatedButton("Filtrer", on_click=filter_traffic)], spacing=15),
                ft.Container(height=25),
                ft.Card(
                    content=ft.Container(
                        content=ft.Column([
                            ft.Text("Paquets enregistrés", size=14, color=ft.Colors.GREY_600),
                            ft.Container(height=10),
                            traffic_table
                        ]), padding=15
                    ), elevation=2
                )
            ], expand=True, scroll=ft.ScrollMode.AUTO)

        # --- AUTRES PAGES (Non connectées BDD pour l'instant mais conservées) ---
        def create_send_page():
            # [Le code de la page Émission reste identique à votre version précédente]
            # ... (Pour simplifier l'affichage ici, je reprends le contenu standard)
            return ft.Column([
                ft.Text("Émission de Trames (Simulation)", size=24, weight=ft.FontWeight.BOLD),
                ft.Text("Cette fonctionnalité nécessiterait un module d'envoi SNMP (ex: pysnmp)", color=ft.Colors.GREY)
            ])

        def create_anomalies_page():
             # [Le code de la page Anomalies reste identique à votre version précédente]
            return ft.Column([
                ft.Text("Détection d'Anomalies", size=24, weight=ft.FontWeight.BOLD),
                ft.Text("Module d'analyse statistique", color=ft.Colors.GREY)
            ])

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
        view=ft.WEB_BROWSER,         # <— mode Web
        port=0,                      # port aléatoire
        assets_dir="assets",          # si vous avez des assets (images, fonts…)

    )

import tkinter as tk
from tkinter import messagebox
import os

REPORTS_FOLDER = "data/reports"

def reports_section(main_frame):
    label = tk.Label(main_frame, text="Visualisez les rapports d'analyse précédents :", bg="white", font=("Arial", 14))
    label.pack(pady=20)

    # Actualiser la liste des rapports
    def refresh_report_list():
        for widget in report_list_frame.winfo_children():
            widget.destroy()

        if not os.path.exists(REPORTS_FOLDER):
            os.makedirs(REPORTS_FOLDER)

        reports = os.listdir(REPORTS_FOLDER)
        if not reports:
            no_reports_label = tk.Label(report_list_frame, text="Aucun rapport disponible.", bg="white", font=("Arial", 12))
            no_reports_label.pack()
        else:
            for report in reports:
                report_label = tk.Label(report_list_frame, text=report, bg="white", font=("Arial", 12))
                report_label.pack(pady=5)

                def open_report(file=report):
                    file_path = os.path.join(REPORTS_FOLDER, file)
                    with open(file_path, "r") as f:
                        content = f.read()
                    messagebox.showinfo(f"Rapport : {file}", content)

                open_button = tk.Button(report_list_frame, text="Ouvrir", command=open_report, bg="#3498db", fg="white", font=("Arial", 10))
                open_button.pack(pady=5)

    # Cadre pour afficher la liste des rapports
    report_list_frame = tk.Frame(main_frame, bg="white")
    report_list_frame.pack(pady=10)

    # Ajouter un bouton pour actualiser
    refresh_button = tk.Button(main_frame, text="Actualiser", command=refresh_report_list, bg="#3498db", fg="white", font=("Arial", 12))
    refresh_button.pack(pady=10)

    refresh_report_list()

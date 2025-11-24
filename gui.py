import os, sys, shutil, glob, subprocess
import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import ttk
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.pyplot as plt
import pandas as pd
import networkx as nx

import cpg_manipulation

class VulnerabilityScannerApp:
    def __init__(self, root):
        root.geometry("1000x1000")
        self.root = root
        self.root.title("TeamTen - Vulnerability Scanner")
        self.file_path = None

        # Upload Button
        self.upload_btn = tk.Button(root, text="Upload File", command=self.upload_file)
        self.upload_btn.pack(pady=10)

        # Status Label
        self.status_label = tk.Label(root, text="No file uploaded yet.", fg="blue")
        self.status_label.pack(pady=5)

        # Scan Button (still available if you want manual rescan)
        self.scan_btn = tk.Button(root, text="Scan for Vulnerabilities", command=self.scan_file)
        self.scan_btn.pack(pady=10)

        # Canvas for Graph
        self.canvas_frame = tk.Frame(root)
        self.canvas_frame.pack(fill=tk.BOTH, expand=True)

        # Select Graph Type
        self.graph_type = tk.StringVar(value="CFG")
        graph_options = ["CFG", "CALL", "AST"]
        #self.graph_menu = tk.OptionMenu(root, self.graph_type, *graph_options)
        #self.graph_menu.pack(pady=10)
        
        self.graph_menu = ttk.Combobox(root, textvariable=self.graph_type, values=graph_options, state="readonly")
        self.graph_menu.pack(pady=10)

        # Bind change event: automatically rescan when graph type changes
        self.graph_menu.bind("<<ComboboxSelected>>", lambda e: self.on_graph_change())

    # ---------------- Upload File ----------------
    def upload_file(self):
        original_path = filedialog.askopenfilename()
        if original_path:
            ext = os.path.splitext(original_path)[1].lower()
            if ext not in ['.c']:
                messagebox.showerror("Invalid File", "Please select a .c file.")
                return

        source_dir = os.path.join(os.getcwd(), "source")
        os.makedirs(source_dir, exist_ok=True)

        # Clean source dir
        for filename in os.listdir(source_dir):
            file_path = os.path.join(source_dir, filename)
            try:
                if os.path.isfile(file_path) or os.path.islink(file_path):
                    os.unlink(file_path)
                elif os.path.isdir(file_path):
                    shutil.rmtree(file_path)
            except Exception as e:
                messagebox.showerror("Cleanup Failed", f"Failed to delete {file_path}: {str(e)}")
                return

        filename = os.path.basename(original_path)
        destination_path = os.path.join(source_dir, filename)

        try:
            shutil.copy2(original_path, destination_path)
            self.file_path = destination_path
            self.status_label.config(text=f"File uploaded: {destination_path}", fg="green")
        except Exception as e:
            self.status_label.config(text=f"Upload failed: {str(e)}", fg="red")
     #       messagebox.showinfo("File Uploaded", f"File saved to: {destination_path}")
     #   except Exception as e:
     #       messagebox.showerror("Upload Failed", f"Error: {str(e)}")

    # ---------------- Scan File ----------------
    def scan_file(self):
        if not self.file_path:
            messagebox.showwarning("No File", "Please upload a file first.")
            return

        code_path = "./source/"
        csv_output_path = "./cpg_output/"

        # Clean old output dir to avoid Joern error
        if os.path.exists(csv_output_path):
            shutil.rmtree(csv_output_path)


        try:
            subprocess.run(["joern-parse", code_path], check=True)
            subprocess.run([
                "joern-export", "--repr=all", "--format=neo4jcsv", "--out", csv_output_path
            ], check=True)
        except subprocess.CalledProcessError as e:
            messagebox.showerror("Joern Error", f"Joern failed: {e}")
            return

        # Build CPG dataframes
        cpg_df = cpg_manipulation.process_csv(csv_output_path)

        selected_graph = self.graph_type.get()
        graph = cpg_manipulation.build_graph(cpg_df, selected_graph)

        # Example: count nodes by label
        if ':LABEL' in cpg_df["nodes"].columns:
            data = cpg_df["nodes"][":LABEL"].value_counts().to_dict()
        else:
            data = {"No labels found": 0}

        self.plot_vulnerabilities(data, selected_graph)

    # ---------------- Auto-trigger on dropdown change ----------------
    def on_graph_change(self, *args):
        if self.file_path:   # only rescan if a file is uploaded
            self.scan_file()

    # ---------------- Plot Vulnerabilities ----------------
    def plot_vulnerabilities(self, data, graph_type):
        for widget in self.canvas_frame.winfo_children():
            widget.destroy()

        fig, ax = plt.subplots(figsize=(6, 4))

        if graph_type == "CFG":
            # bar chart
            ax.bar(data.keys(), data.values(), color='tomato')
            ax.set_ylabel("Occurrences")
            ax.set_xlabel("Feature")

        elif graph_type == "CALL":
            # pie chart
            ax.pie(data.values(), labels=data.keys(), autopct='%1.1f%%', startangle=90)
            ax.set_ylabel("")
            ax.set_xlabel("")

        elif graph_type == "AST":
            # line chart
            ax.plot(list(data.keys()), list(data.values()), marker='o', color='blue')
            ax.set_ylabel("Occurrences")
            ax.set_xlabel("Feature")

        ax.set_title(f"{graph_type} Graph Analysis")
        ax.tick_params(axis='x', rotation=45)

        canvas = FigureCanvasTkAgg(fig, master=self.canvas_frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

if __name__ == "__main__":
    root = tk.Tk()
    app = VulnerabilityScannerApp(root)
    root.mainloop()

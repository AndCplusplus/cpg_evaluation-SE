import os, shutil, subprocess
import cpg_manipulation
import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import ttk
import pandas as pd
import networkx as nx
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg


class VulnerabilityScannerApp:
    def __init__(self, root):
        root.geometry("1000x1000")
        self.root = root
        self.root.title("TeamTen - Vulnerability Scanner")
        self.file_path = None
        self.graph = None
        self.graph_positions = {}

        # Upload Button
        self.upload_btn = tk.Button(root, text="Upload File", command=self.upload_file)
        self.upload_btn.pack(pady=10)

        # Status Label (Text widget for colored filename)
        self.status_label = tk.Text(root, height=1, width=80, borderwidth=0, background=root.cget("bg"))
        self.status_label.pack(pady=5)
        self.status_label.config(state=tk.DISABLED)

        # Graph Type Dropdown
        self.graph_type = tk.StringVar(value="Select Graph to Display")
        graph_options = ["CFG", "CALL", "AST"]
        self.graph_menu = ttk.Combobox(root, textvariable=self.graph_type,
                                       values=graph_options, state="readonly")
        self.graph_menu.pack(pady=10)
        self.graph_menu.bind("<<ComboboxSelected>>", lambda e: self.on_graph_change())

        # Canvas for Graph
        self.canvas_frame = tk.Frame(root)
        self.canvas_frame.pack(fill=tk.BOTH, expand=True)

        # Vulnerability Table at bottom
        self.table_frame = tk.Frame(root)
        self.table_frame.pack(fill=tk.X, side=tk.BOTTOM, pady=10)

        columns = ("method", "line", "vulnerability", "severity")
        self.vuln_table = ttk.Treeview(self.table_frame, columns=columns, show="headings", height=6)

        # Define headings
        self.vuln_table.heading("method", text="Method")
        self.vuln_table.heading("line", text="Line")
        self.vuln_table.heading("vulnerability", text="Vulnerability")
        self.vuln_table.heading("severity", text="Severity")

        # Define column widths
        self.vuln_table.column("method", width=200, anchor="center")
        self.vuln_table.column("line", width=80, anchor="center")
        self.vuln_table.column("vulnerability", width=250, anchor="center")
        self.vuln_table.column("severity", width=120, anchor="center")

        self.vuln_table.pack(fill=tk.X)

        # Severity row coloring
        self.vuln_table.tag_configure("HIGH", background="lightcoral")
        self.vuln_table.tag_configure("MEDIUM", background="khaki")
        self.vuln_table.tag_configure("LOW", background="lightgreen")
    # ---------------- Upload File ----------------
    def upload_file(self):
        original_path = filedialog.askopenfilename()
        if not original_path:
            return
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
            self.update_status(destination_path)
        except Exception as e:
            self.show_error(f"Upload failed: {str(e)}")

    # ---------------- Update Status ----------------
    def update_status(self, full_path):
        self.status_label.config(state=tk.NORMAL)
        self.status_label.delete("1.0", tk.END)

        filename = os.path.basename(full_path)

        self.status_label.insert(tk.END, "Current File: ", "static")
        self.status_label.insert(tk.END, filename, "filename")

        self.status_label.tag_config("static", foreground="black", justify="center")
        self.status_label.tag_config("filename", foreground="green", font=("TkDefaultFont", 10, "bold"), justify="center")

        self.status_label.tag_add("center", "1.0", "end")
        self.status_label.tag_config("center", justify="center")

        self.status_label.config(state=tk.DISABLED)

    def show_error(self, msg):
        self.status_label.config(state=tk.NORMAL)
        self.status_label.delete("1.0", tk.END)
        self.status_label.insert(tk.END, msg, "error")
        self.status_label.tag_config("error", foreground="red", justify="center")
        self.status_label.tag_add("center", "1.0", "end")
        self.status_label.tag_config("center", justify="center")
        self.status_label.config(state=tk.DISABLED)

    # ---------------- Scan File ----------------
    def scan_file(self):
        if not self.file_path:
            messagebox.showwarning("No File", "Please upload a file first.")
            return

        code_path = "./source/"
        csv_output_path = "./cpg_output/"

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
        self.graph = cpg_manipulation.build_graph(cpg_df, selected_graph)

        # Example vulnerability report (replace with actual Joern scan result )<--------------------------------------------------
        vuln_report_df = pd.DataFrame([{
            'severity': 'HIGH',
            'type': 'Dangerous function',
            'filename': 'example.c',
            'line': 8,
            'caller': 'main'
        }])

        vuln_caller = vuln_report_df['caller'][0]
        color_map = cpg_manipulation.color_nodes(self.graph, vuln_caller)

        # Show graph inside GUI
        self.plot_graph(self.graph, 'METHOD_FULL_NAME:string', color_map, selected_graph)

        # Populate vulnerability table
        for row in self.vuln_table.get_children():
            self.vuln_table.delete(row)

        for _, row in vuln_report_df.iterrows():
            self.vuln_table.insert("", tk.END, values=(
                row['caller'], row['line'], row['type'], row['severity']
            ), tags=(row['severity'],))

        messagebox.showinfo("Graph Displayed",
                            f"{selected_graph} graph shown with vulnerable caller: {vuln_caller}")

    # ---------------- Auto-trigger on dropdown change ----------------
    def on_graph_change(self):
        self.scan_file()

    # ---------------- Plot Graphs ----------------
    def plot_graph(self, graph, feature, node_colors, graph_type):
        # Clear previous canvas
        for widget in self.canvas_frame.winfo_children():
            widget.destroy()

        labels = {node: data.get(feature, node) for node, data in graph.nodes(data=True)}
        color_map = [node_colors.get(node, 'cyan') for node in graph.nodes()]

        fig, ax = plt.subplots(figsize=(8, 6))
        pos = self.graph_positions.get(graph_type) or nx.spring_layout(graph, seed=42)
        self.graph_positions[graph_type] = pos

        nx.draw(graph, pos, labels=labels, with_labels=True, ax=ax,
                node_color=color_map, arrows=True)
        ax.set_title(f"{graph_type} Graph Visualization")

        canvas = FigureCanvasTkAgg(fig, master=self.canvas_frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

        # --- Bind click event to show node info ---
        def on_click(event):
            if event.inaxes is not None:
                closest_node = None
                min_dist = float("inf")
                for node, (x, y) in pos.items():
                    dist = (event.xdata - x)**2 + (event.ydata - y)**2
                    if dist < min_dist:
                        min_dist = dist
                        closest_node = node

                if closest_node is not None:
                    node_data = graph.nodes[closest_node]
                    info = "\n".join([f"{k}: {v}" for k, v in node_data.items()])
                    messagebox.showinfo("Node Information",
                                        f"Node: {closest_node}\n{info}")

        canvas.mpl_connect("button_press_event", on_click)


# ---------------- Main Entry ----------------
if __name__ == "__main__":
    root = tk.Tk()
    app = VulnerabilityScannerApp(root)
    root.mainloop()

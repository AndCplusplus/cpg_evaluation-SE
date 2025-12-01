import os, shutil, subprocess
import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import ttk
import pandas as pd
import networkx as nx
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

from joern import run_joern_scan, run_joern_parse, run_joern_export
import cpg_manipulation

class VulnerabilityScannerApp:
    def __init__(self, root):
        root.geometry("1000x1000")
        self.root = root
        self.root.title("TeamTen - Vulnerability Scanner")
        self.file_path = None
        self.graph = None

        # Store results once per scan
        self.vuln_report_df = None
        self.cpg_df = None

        # Upload Button
        self.upload_btn = tk.Button(root, text="Upload File", command=self.upload_file)
        self.upload_btn.pack(pady=10)

        # Status Label
        self.status_label = tk.Text(root, height=1, width=80, background=root.cget("bg"))
        self.status_label.pack(pady=5)
        self.status_label.config(state=tk.DISABLED)

        # Scan Button
        self.scan_btn = tk.Button(root, text="Scan for Vulnerabilities", command=self.scan_file)
        self.scan_btn.pack(pady=10)

        # Graph Type Dropdown (can be moved above/below as you prefer)
        self.graph_type = tk.StringVar(value="CFG")
        graph_options = ["CFG", "CALL", "AST"]
        self.graph_menu = ttk.Combobox(root, textvariable=self.graph_type,
                                       values=graph_options, state="readonly")
        self.graph_menu.pack(pady=10)
        self.graph_menu.bind("<<ComboboxSelected>>", lambda e: self.on_graph_change())

        # Canvas for Graph
        self.canvas_frame = tk.Frame(root)
        self.canvas_frame.pack(fill=tk.BOTH, expand=True)

        # Table
        self.table_frame = tk.Frame(root)
        self.table_frame.pack(fill=tk.BOTH, expand=True)


    
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

            # Reset previous scan results when a new file is uploaded
            self.vuln_report_df = None
            self.cpg_df = None
            self.clear_graph()
        except Exception as e:
            messagebox.showerror("Upload Failed", f"Error: {str(e)}")

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
        # fix tag name
        self.status_label.tag_add("center", "1.0", "end")
        self.status_label.tag_config("center", justify="center")
        self.status_label.config(state=tk.DISABLED)

    def clear_graph(self):
        for widget in self.canvas_frame.winfo_children():
            widget.destroy()

    # ---------------- Scan File ONCE ----------------
    def scan_file(self):
        if not self.file_path:
            messagebox.showwarning("No File", "Please upload a file first.")
            return

        code_path = "./source/"
        csv_output_path = "./cpg_output/"

        # Fresh export directory
        if os.path.exists(csv_output_path):
            shutil.rmtree(csv_output_path)
        # os.makedirs(csv_output_path, exist_ok=True) # do not make directory

        # 1) Vulnerability scan -> DataFrame
        try:
            self.vuln_report_df = run_joern_scan(code_path)
        except subprocess.CalledProcessError as e:
            messagebox.showerror("joern-scan Error", f"Joern failed: {e}")
            return
        except Exception as e:
            messagebox.showerror("Scan Error", f"Scan failed: {e}")
            return

        # 2) Parse and Export CPG
        try:
            # If you use joern CLI directly
            subprocess.run(["joern-parse", code_path], check=True)
            subprocess.run(["joern-export", "--repr=all", "--format=neo4jcsv", "--out", csv_output_path], check=True)

            # Or if you prefer the imported wrappers:
            # run_joern_parse(code_path)
            # run_joern_export(repr_type="all", fmt="neo4jcsv", out_dir=csv_output_path)
        except subprocess.CalledProcessError as e:
            messagebox.showerror("joern-parse/export Error", f"Joern failed: {e}")
            return
        except FileNotFoundError:
            messagebox.showerror("Joern Not Found", "joern-parse or joern-export not found in PATH.")
            return

        # 3) Process CPG once
        try:
            self.cpg_df = cpg_manipulation.process_csv(csv_output_path)
        except Exception as e:
            messagebox.showerror("CPG Processing Error", f"Failed to process CPG CSVs: {e}")
            return

        # 4) Build initial graph (using current dropdown selection)
        self.build_and_plot_graph()

        # Optional info about vuln caller if present
        if isinstance(self.vuln_report_df, pd.DataFrame) and not self.vuln_report_df.empty and "caller" in self.vuln_report_df.columns:
            vuln_caller = self.vuln_report_df.iloc[0]["caller"]
            messagebox.showinfo("Graph Displayed", f"{self.graph_type.get()} graph shown with vulnerable caller: {vuln_caller}")
        else:
            messagebox.showinfo("Graph Displayed", f"{self.graph_type.get()} graph shown.")





    # ---------------- Build Table ---------------------------------
    
    def show_vuln_table(self):                                                                  #
        # Clear previous table                                                                  #
                                                                                                #
        for widget in self.table_frame.winfo_children():                                        #
            widget.destroy()                                                                    #
                                                                                                #
        if not isinstance(self.vuln_report_df, pd.DataFrame) or self.vuln_report_df.empty:      #
            tk.Label(self.table_frame, text="No vulnerabilities found").pack()                  #
            return                                                                              #
                                                                                                #
        # Create Treeview                                                                       #
        columns = ("Method", "Line", "Type", "Severity")                                        #
        tree = ttk.Treeview(self.table_frame, columns=columns, show="headings")                 #
                                                                                                #
        # Define headings                                                                       #
        for col in columns:                                                                     #
            tree.heading(col, text=col)                                                         #
            tree.column(col, width=150, anchor="center")                                        #
                                                                                                #
        # Insert rows from DataFrame                                                            #
        for _, row in self.vuln_report_df.iterrows():                                           #
            tree.insert("", tk.END, values=(                                                    #
                row.get("caller", ""),                                                          #
                row.get("line", ""),                                                            #
                row.get("type", ""),                                                            #
                row.get("severity", "")                                                         #
            ))                                                                                  #
                                                                                                #
        tree.pack(fill=tk.BOTH, expand=True)                                                    #

    # ---------------- Build & Plot from stored data ----------------
    def build_and_plot_graph(self):
        if self.cpg_df is None:
            messagebox.showinfo("Scan First", "Please run the scan once before switching graphs.")
            return

        selected_graph = self.graph_type.get()

        # Build graph from stored CPG data
        try:
            self.graph = cpg_manipulation.build_graph(self.cpg_df, selected_graph)
        except Exception as e:
            messagebox.showerror("Graph Build Error", f"Failed to build {selected_graph} graph: {e}")
            return

        # Determine vulnerable caller for coloring (if available)
        vuln_caller = None
        if isinstance(self.vuln_report_df, pd.DataFrame) and not self.vuln_report_df.empty and "caller" in self.vuln_report_df.columns:
            vuln_caller = self.vuln_report_df.iloc[0]["caller"]

        try:
            color_map = cpg_manipulation.color_nodes(self.graph, vuln_caller) if vuln_caller else {}
        except Exception:
            color_map = {}

        # Plot using the stored data
        self.plot_graph(self.graph, 'METHOD_FULL_NAME:string', color_map, selected_graph)

    # ---------------- Dropdown change: reuse data ----------------
    def on_graph_change(self):
        # Do NOT rescan; reuse stored CPG and vuln_report
        self.build_and_plot_graph()

    # ---------------- Plot Graphs ----------------
    def plot_graph(self, graph, feature, node_colors, graph_type):
        # Clear previous canvas
        self.clear_graph()

        labels = {node: data.get(feature, node) for node, data in graph.nodes(data=True)}
        color_map = [node_colors.get(node, 'cyan') for node in graph.nodes()]

        fig, ax = plt.subplots(figsize=(8, 6))
        pos = nx.spring_layout(graph, seed=42)
        nx.draw(graph, pos, labels=labels, with_labels=True, ax=ax,
                node_color=color_map, arrows=True)
        ax.set_title(f"{graph_type} Graph Visualization")

        canvas = FigureCanvasTkAgg(fig, master=self.canvas_frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

        # Bind click event to show node info
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
        plt.close(fig)  # prevent memory growth across redraws
        self.show_vuln_table()                                                                   #

if __name__ == "__main__":
    root = tk.Tk()
    app = VulnerabilityScannerApp(root)
    root.mainloop()

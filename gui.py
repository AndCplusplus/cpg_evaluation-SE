# Better safe then sorry with the imports will trim later
import os
import sys
# print("Running with Python:", sys.executable)
import tkinter as tk
from tkinter import filedialog, messagebox
# this was causing issues for me
#from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.pyplot as plt
import shutil

class VulnerabilityScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Vulnerability Scanner")
        self.file_path = None

        # Upload Button
        self.upload_btn = tk.Button(root, text="Upload File", command=self.upload_file)
        self.upload_btn.pack(pady=10)

        # Scan Button
        self.scan_btn = tk.Button(root, text="Scan for Vulnerabilities", command=self.scan_file)
        self.scan_btn.pack(pady=10)

        # Canvas for Graph
        self.canvas_frame = tk.Frame(root)
        self.canvas_frame.pack(fill=tk.BOTH, expand=True)

#  -----------  UPLOAD FILE FUNCTION  -----------
    def upload_file(self):
#        self.file_path = filedialog.askopenfilename()
#        if self.file_path:
#            messagebox.showinfo("File Selected", f"Selected: {self.file_path}")
        original_path = filedialog.askopenfilename(
            filetypes=[("C Source Files", "*.c")]
        )
        if original_path:
            ext = os.path.splitext(original_path)[1].lower()
            if ext not in ['.c']:
                messagebox.showerror("Invalid File", "Please select a .c file.")
                return

        #  -----------  EMPTY SOURCE FOLDER BEFORE UPLOAD  -----------
        source_dir = os.path.join(os.getcwd(), "source")
        os.makedirs(source_dir, exist_ok=True)

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
        #  -------------------------------------------------------------

        
        filename = os.path.basename(original_path)
        destination_path = os.path.join(source_dir, filename)

        try:
            shutil.copy2(original_path, destination_path)
            self.file_path = destination_path
            messagebox.showinfo("File Uploaded", f"File saved to: {destination_path}")
        except Exception as e:
            messagebox.showerror("Upload Failed", f"Error: {str(e)}")



#  -----------  UPLOAD FILE FUNCTION  -----------




#  -----------  SCAN FILE FUNCTION  -----------
    def scan_file(self):
        if not self.file_path:
            messagebox.showwarning("No File", "Please upload a file first.")
            return

        # Placeholder: Replace with your actual scanning logic
        vulnerabilities = self.mock_scan(self.file_path)

        # Generate graph
        self.plot_vulnerabilities(vulnerabilities)

    def mock_scan(self, path):
        # Replace with real scanning logic
        return {
            "SQL Injection": 3,
            "XSS": 5,
            "CSRF": 2,
            "Open Redirect": 1
        }
#  -----------  SCAN FILE FUNCTION  -----------


#  -----------  PLOT VULNERABILITY FUNCTION  -----------
    def plot_vulnerabilities(self, data):
        for widget in self.canvas_frame.winfo_children():
            widget.destroy()

        fig, ax = plt.subplots(figsize=(6, 4))
        ax.bar(data.keys(), data.values(), color='tomato')
        ax.set_title("Vulnerability Scan Results")
        ax.set_ylabel("Occurrences")
        ax.set_xlabel("Vulnerability Type")
        ax.tick_params(axis='x', rotation=45)

        canvas = FigureCanvasTkAgg(fig, master=self.canvas_frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

#  -----------  PLOT VULNERABILITY FUNCTION  -----------


if __name__ == "__main__":
    root = tk.Tk()
    app = VulnerabilityScannerApp(root)
    root.mainloop()

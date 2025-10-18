import pandas as pd
import matplotlib.pyplot as plt
import networkx as nx
import subprocess
import cpg_manipulation
import joernscan


# assign the directory containing code to scan
code_path = "./source/"

# use joernscan module to run the scan
scan_result = joernscan.run_joern_scan(code_path)


vuln_df = pd.DataFrame.from_dict(scan_result, orient='index')

vreport = joernscan.parse_result_line(vuln_df.iloc[0,0])

vuln_report_df = pd.DataFrame([vreport],
    columns=['severity', 'type', 'filename', 'line', 'caller']
)
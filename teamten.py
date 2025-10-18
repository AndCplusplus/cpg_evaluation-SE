import pandas as pd
import matplotlib.pyplot as plt
import networkx as nx
import subprocess
import cpg_manipulation
import joernscan


# assign the directory containing code to scan
code_path = "./source/"
# add check if folder already exists and if so delete it
csv_output_path = "./cpg_output/"

# use joernscan module to run the scan
scan_result = joernscan.run_joern_scan(code_path)
vuln_df = pd.DataFrame.from_dict(scan_result, orient='index')
vreport = joernscan.parse_result_line(vuln_df.iloc[0,0])

# create a dataframe from the vulnerability report
vuln_report_df = pd.DataFrame([vreport],
    columns=['severity', 'type', 'filename', 'line', 'caller']
)

# create cpg.bin
joernscan.run_joern_parse(code_path)

# export cpg to csv files
joernscan.run_joern_export(csv_output_path)

# create cpg dataframes from exported csv files
cpg_df = cpg_manipulation.process_csv(csv_output_path)
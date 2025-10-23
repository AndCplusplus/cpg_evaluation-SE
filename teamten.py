import pandas as pd
import cpg_manipulation
import joern

# todo add folder cleaning

# assign the directory containing code to scan
code_path = "./source/"
# add check if folder already exists and if so delete it
csv_output_path = "./cpg_output/"

# use joernscan module to run the scan
scan_result = joern.run_joern_scan(code_path)
vuln_df = pd.DataFrame.from_dict(scan_result, orient='index')
vreport = joern.parse_result_line(vuln_df.iloc[0,0])

# create a dataframe from the vulnerability report
vuln_report_df = pd.DataFrame([vreport],
    columns=['severity', 'type', 'filename', 'line', 'caller']
)

# create cpg.bin
joern.run_joern_parse(code_path)

# export cpg to csv files
joern.run_joern_export(csv_output_path)


# create cpg dataframes from exported csv files
cpg_df = cpg_manipulation.process_csv(csv_output_path)
#refactor to handle any sub graph
boflow_AST = cpg_manipulation.build_graph(cpg_df, 'AST')
boflow_CALL = cpg_manipulation.build_graph(cpg_df, 'CALL')
boflow_CFG = cpg_manipulation.build_graph(cpg_df, 'CFG')

color_map = cpg_manipulation.color_nodes(boflow_AST, 'METHOD_FULL_NAME:string', vuln_caller)

vuln_caller = vuln_report_df['caller'][0]
vuln_nodes = [n for n, d in boflow_AST.nodes(data=True) if d.get('METHOD_FULL_NAME:string') == vuln_caller]

cpg_manipulation.visualize_aug_graph(boflow_AST, 'METHOD_FULL_NAME:string', color_map)

import os
import glob
import pandas as pd
import networkx as nx
import matplotlib.pyplot as plt


def consolidate_csv(pattern):
    data_suffix="_data.csv"
    header_suffix="_header.csv"
    files = glob.glob(pattern)
    dfs = []
    for file in files:
        # Derive header filename: replace the data_suffix with header_suffix
        header_file = file.replace(data_suffix, header_suffix)
        if os.path.exists(header_file):
            # use header.csv to name columns
            with open(header_file, 'r') as hf:
                header_line = hf.readline().strip()
                columns = header_line.split(',')
            df = pd.read_csv(file, header=None, names=columns)
            dfs.append(df)
        else:
            print(f"Header file {header_file} not found for data file {file}.")
    if dfs:
        return pd.concat(dfs, ignore_index=True)
    else:
        return pd.DataFrame()
    
def process_csv(directory):
    cpg_df = {}
    print(f"Processing {directory}")
    nodes_pattern = os.path.join(directory, "nodes_*_data.csv")
    edges_pattern = os.path.join(directory, "edges_*_data.csv")
    
    nodes_df = consolidate_csv(nodes_pattern)
    edges_df = consolidate_csv(edges_pattern)
    
    cpg_df = {"nodes": nodes_df, "edges": edges_df}
    return cpg_df


def build_graph(cpg: dict, subgraph: str) -> nx.DiGraph:
    subgraph = subgraph.upper()
    graph = nx.DiGraph()

    edges = cpg["edges"]
    edges = edges[edges[':TYPE'] == subgraph]

    sub_nodes = set(edges[':START_ID']).union(set(edges[':END_ID']))

    for node in sub_nodes:
        node_attr = {}
        if node in cpg["nodes"][":ID"].values:
            node_attr = cpg['nodes'][cpg['nodes'][':ID'] == node].iloc[0].to_dict()
        graph.add_node(node, **node_attr)

    for _, row in edges.iterrows():
        src = row[':START_ID']
        tgt = row[':END_ID']
        graph.add_edge(src, tgt, **row.to_dict())

    return graph

def visualize_graph(graph, feature):
    labels = {node: data.get(feature, node) for node, data in graph.nodes(data=True)}
    fig, ax = plt.subplots(figsize=(10, 8))
    pos = nx.spring_layout(graph, seed=42)
    nx.draw(graph, pos, labels=labels, with_labels=True, ax=ax, node_color='orange', arrows=True)
    plt.show()

def visualize_aug_graph(graph, feature, node_colors=None, default_color='cyan'):
    labels = {node: data.get(feature, node) for node, data in graph.nodes(data=True)}
    if node_colors is None:
      node_colors = {}

    color_map = [node_colors.get(node, default_color) for node in graph.nodes()]
    fig, ax = plt.subplots(figsize=(10, 8))
    pos = nx.spring_layout(graph, seed=42)
    nx.draw(graph, pos, labels=labels, with_labels=True, ax=ax, node_color=color_map, arrows=True)
    plt.show()

def color_nodes(graph, vuln_caller):
    node_colors = {}
    for node, data in graph.nodes(data=True):
        if data.get('METHOD_FULL_NAME:string') == vuln_caller:
            node_colors[node] = 'red' 
    return node_colors

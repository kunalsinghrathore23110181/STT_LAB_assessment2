import re
import networkx as nxs
import matplotlib.pyplot as plt
from networkx.drawing.nx_pydot import write_dot
import os

# ---------- Step 1: Read and clean code ----------
def read_code(filename):
    with open(filename, "r") as f:
        lines = [line.strip() for line in f.readlines() if line.strip()]
    return lines

# ---------- Step 2: Identify leaders ----------
def find_leaders(lines):
    leaders = set()
    if lines:
        leaders.add(1)
    for i, line in enumerate(lines):
        if re.search(r'\bif\b|\bwhile\b|\bfor\b', line):
            leaders.add(i + 1)
            if i + 2 <= len(lines):
                leaders.add(i + 2)
    return sorted(list(leaders))

# ---------- Step 3: Make basic blocks ----------
def make_basic_blocks(lines, leaders):
    blocks = []
    for i, leader in enumerate(leaders):
        start = leader - 1
        end = (leaders[i + 1] - 2) if i + 1 < len(leaders) else len(lines) - 1
        block = lines[start:end + 1]
        blocks.append((leader, block))
    return blocks

# ---------- Step 4: Build CFG ----------
def build_cfg(blocks):
    G = nx.DiGraph()
    for leader, _ in blocks:
        G.add_node(f"B{leader}")
    for i, (leader, block) in enumerate(blocks):
        if i + 1 < len(blocks):
            G.add_edge(f"B{leader}", f"B{blocks[i + 1][0]}")
        if any(keyword in " ".join(block) for keyword in ["if", "while", "for"]):
            if i + 1 < len(blocks):
                G.add_edge(f"B{leader}", f"B{blocks[i + 1][0]}")
    return G

# ---------- Step 5: Compute metrics ----------
def compute_metrics(G):
    N = G.number_of_nodes()
    E = G.number_of_edges()
    CC = E - N + 2
    return N, E, CC

# ---------- Step 6: Reaching Definitions ----------
def reaching_definitions(blocks):
    all_defs = []
    def_map = {}
    counter = 1

    for leader, block in blocks:
        gen = set()
        kill = set()
        for line in block:
            match = re.match(r'(\w+)\s*=', line)
            if match:
                var = match.group(1)
                def_id = f"D{counter}"
                counter += 1
                def_map[def_id] = f"{var} (in block B{leader})"
                gen.add(def_id)
                kill |= {d for d, v in def_map.items() if v.startswith(var) and d not in gen}
        all_defs.append((f"B{leader}", gen, kill))

    return def_map, all_defs

# ---------- Step 7: Display everything ----------
def main():
    filename = "calc.c"
    lines = read_code(filename)

    leaders = find_leaders(lines)
    blocks = make_basic_blocks(lines, leaders)

    print("\n--- BASIC BLOCKS ---")
    for leader, block in blocks:
        print(f"\nB{leader}:")
        for line in block:
            print("   ", line)

    G = build_cfg(blocks)

    print("\n--- CFG EDGES ---")
    for edge in G.edges():
        print(edge)

    N, E, CC = compute_metrics(G)
    print("\n--- METRICS ---")
    print(f"Number of Nodes (N): {N}")
    print(f"Number of Edges (E): {E}")
    print(f"Cyclomatic Complexity (CC): {CC}")

    def_map, all_defs = reaching_definitions(blocks)
    print("\n--- REACHING DEFINITIONS ---")
    for block, gen, kill in all_defs:
        print(f"{block}: gen={gen}, kill={kill}")

    print("\nDefinition Mapping:")
    for d, desc in def_map.items():
        print(f"{d}: {desc}")

    # ---------- Save DOT + PNG ----------
    write_dot(G, "cfg.dot")
    os.system("dot -Tpng cfg.dot -o cfg.png")
    print("\nCFG saved as cfg.png")

    # Show graph
    pos = nx.spring_layout(G)
    nx.draw(G, pos, with_labels=True, node_color="lightblue", node_size=1800, arrows=True)
    plt.title("Control Flow Graph")
    plt.show()

if __name__ == "__main__":
    main()

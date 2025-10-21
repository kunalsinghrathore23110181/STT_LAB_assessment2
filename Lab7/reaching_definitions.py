# reaching_definitions.py
import re
import networkx as nx
import matplotlib.pyplot as plt

# --- Step 1: Simple parser to extract assignments (definitions) ---
def extract_definitions(lines):
    defs = {}
    def_id = 1
    for i, line in enumerate(lines, start=1):
        line = line.strip()
        # Match simple assignments like x = 5, sum = sum + i, etc.
        if re.match(r'^\w+\s*=', line):
            defs[f"D{def_id}"] = {"line": i, "stmt": line}
            def_id += 1
    return defs

# --- Step 2: Create basic blocks manually (very simplified) ---
def make_basic_blocks(lines):
    blocks = {}
    b_id = 1
    current_block = []
    for i, line in enumerate(lines):
        current_block.append(line.strip())
        if "if" in line or "while" in line or "for" in line:
            blocks[f"B{b_id}"] = current_block
            b_id += 1
            current_block = []
    if current_block:
        blocks[f"B{b_id}"] = current_block
    return blocks

# --- Step 3: Compute gen/kill/in/out ---
def compute_reaching_defs(blocks, defs):
    gen = {}
    kill = {}
    variables = {d["stmt"].split("=")[0].strip() for d in defs.values()}

    # Map variable → list of definition IDs
    var_to_defs = {v: [] for v in variables}
    for d_id, d in defs.items():
        var = d["stmt"].split("=")[0].strip()
        var_to_defs[var].append(d_id)

    # compute gen/kill
    for b, stmts in blocks.items():
        gen[b] = set()
        kill[b] = set()
        for stmt in stmts:
            for d_id, d in defs.items():
                if d["stmt"] == stmt:
                    gen[b].add(d_id)
                    var = d["stmt"].split("=")[0].strip()
                    # kills all other defs of the same var
                    kill[b].update(set(var_to_defs[var]) - {d_id})

    # initialize in/out
    in_sets = {b: set() for b in blocks}
    out_sets = {b: set() for b in blocks}

    changed = True
    while changed:
        changed = False
        for i, b in enumerate(blocks):
            preds = []
            if i > 0:
                preds = [list(blocks.keys())[i - 1]]
            new_in = set().union(*[out_sets[p] for p in preds]) if preds else set()
            new_out = gen[b].union(new_in - kill[b])
            if new_in != in_sets[b] or new_out != out_sets[b]:
                in_sets[b] = new_in
                out_sets[b] = new_out
                changed = True
    return gen, kill, in_sets, out_sets

# --- Step 4: Display results ---
def display(defs, gen, kill, in_sets, out_sets):
    print("\n--- DEFINITIONS ---")
    for d_id, d in defs.items():
        print(f"{d_id}: line {d['line']} -> {d['stmt']}")

    print("\n--- DATAFLOW TABLE ---")
    print(f"{'Block':<5} | {'gen[B]':<10} | {'kill[B]':<10} | {'in[B]':<15} | {'out[B]':<15}")
    print("-" * 65)
    for b in gen:
        print(f"{b:<5} | {str(gen[b]):<10} | {str(kill[b]):<10} | {str(in_sets[b]):<15} | {str(out_sets[b]):<15}")

# --- Step 5: Main ---
if __name__ == "__main__":
    fname = input("Enter C program filename (e.g., example_demo.c): ").strip()
    with open(fname) as f:
        lines = f.readlines()

    defs = extract_definitions(lines)
    blocks = make_basic_blocks(lines)
    gen, kill, ins, outs = compute_reaching_defs(blocks, defs)
    display(defs, gen, kill, ins, outs)

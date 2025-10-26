#!/usr/bin/env python3
"""
auditconfig.py - Compare IOS config (router.cfg) against cmds.txt template
and output minimal correction configs containing only missing commands,
preserving parent hierarchy and indentation.

Features:
- '!' separators between top-level sections for readability.
- Timestamp (YYYYMMDD-HH-MM) added to beginning of correction filename.
"""

import os
import sys
from datetime import datetime

SKIP_MARKER = "!!!"

class Node:
    def __init__(self, cmd, indent):
        self.cmd = cmd
        self.indent = indent
        self.children = []

def parse_config(lines):
    """Parse indented IOS config into a tree of Node objects."""
    root = Node("__root__", -1)
    stack = [root]

    for raw in lines:
        line = raw.rstrip()
        if not line:
            continue
        stripped = line.lstrip()
        if stripped.startswith("!") or SKIP_MARKER in stripped:
            continue
        indent = len(line) - len(stripped)
        node = Node(stripped, indent)
        while stack and stack[-1].indent >= indent:
            stack.pop()
        stack[-1].children.append(node)
        stack.append(node)

    return root

def tree_to_paths(node, parent_path=()):
    """Flatten a tree into (path, indent) tuples."""
    paths = []
    for child in node.children:
        path = parent_path + (child.cmd,)
        paths.append((path, child.indent))
        paths.extend(tree_to_paths(child, path))
    return paths

def build_path_lookup(node):
    """Return set of all command paths in this config tree."""
    return {path for path, _ in tree_to_paths(node)}

def generate_missing(template_node, device_lookup, prefix=(), top_level=False):
    """
    Recursively find missing template lines.
    If any child is missing, include the parent line as well.
    top_level=True means we’re at a direct child of root.
    """
    missing_blocks = []

    for child in template_node.children:
        path = prefix + (child.cmd,)
        if path not in device_lookup:
            # Entire branch missing — include subtree
            block = render_subtree(child)
            if top_level and block:
                block.insert(0, "!")  # add separator before top-level block
            missing_blocks.append(block)
        else:
            # Parent exists — check for missing children
            child_missing = generate_missing(child, device_lookup, path, False)
            if child_missing:
                block = [(" " * child.indent) + child.cmd] + child_missing
                if top_level:
                    block.insert(0, "!")
                missing_blocks.append(block)

    # Flatten nested blocks to a single list
    flat_lines = []
    for blk in missing_blocks:
        flat_lines.extend(blk)
    return flat_lines

def render_subtree(node):
    """Render this node and all descendants as indented lines."""
    lines = [(" " * node.indent) + node.cmd]
    for c in node.children:
        lines.extend(render_subtree(c))
    return lines

def main(cfg_dir):
    # Load template
    try:
        with open("cmds.txt") as f:
            tmpl_lines = f.readlines()
    except FileNotFoundError:
        print("Error: cmds.txt not found.")
        sys.exit(1)

    template_root = parse_config(tmpl_lines)
    out_dir = "corrections"
    os.makedirs(out_dir, exist_ok=True)

    timestamp_before = str(datetime.now().strftime("%Y%m%d:%H:%M"))
    timestamp = timestamp_before.replace(":", "-")

    for root, _, files in os.walk(cfg_dir):
        for file in files:
            if not file.endswith(".cfg"):
                continue

            cfg_path = os.path.join(root, file)
            with open(cfg_path) as f:
                cfg_lines = f.readlines()

            device_root = parse_config(cfg_lines)
            device_lookup = build_path_lookup(device_root)

            missing_lines = generate_missing(template_root, device_lookup, top_level=True)

            # Remove leading '!' if it's the first line
            if missing_lines and missing_lines[0] == "!":
                missing_lines = missing_lines[1:]

            if missing_lines:
                base_name = os.path.splitext(file)[0]
                out_name = f"{timestamp}-{base_name}_correction.cfg"
                out_path = os.path.join(out_dir, out_name)
                with open(out_path, "w") as out:
                    out.write("\n".join(missing_lines) + "\n")
                print(f"Correction file created: {out_name}")
            else:
                print(f"No corrections needed for {file}")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        cfg_dir = sys.argv[1]
    else:
        cfg_dir = "./ios"
    if not os.path.isdir(cfg_dir):
        print(f"Error: {cfg_dir} not found.")
        sys.exit(1)
    main(cfg_dir)

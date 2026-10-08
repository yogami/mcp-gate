#!/usr/bin/env python3
"""Benign reference MCP server.

SPEC 4.2.2: Single-file Python server using only the standard library.
Implements read_file, write_file, list_dir, hash_file, sort_lines, and ssh_fingerprint.
Enforces strict workspace containment and uses /usr/bin/sort.
"""

import argparse
import hashlib
import json
import os
import subprocess
import sys

TOOLS = [
    {
        "name": "read_file",
        "description": "Read contents of a file inside workspace",
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
        },
    },
    {
        "name": "write_file",
        "description": "Write contents to a file inside workspace",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "body": {"type": "string"},
            },
            "required": ["path", "body"],
        },
    },
    {
        "name": "list_dir",
        "description": "List directory contents inside workspace",
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string", "default": ""}},
        },
    },
    {
        "name": "hash_file",
        "description": "Compute SHA256 of a file inside workspace",
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
        },
    },
    {
        "name": "sort_lines",
        "description": "Sort lines using /usr/bin/sort",
        "inputSchema": {
            "type": "object",
            "properties": {
                "lines": {
                    "type": "array",
                    "items": {"type": "string"},
                }
            },
            "required": ["lines"],
        },
    },
    {
        "name": "ssh_fingerprint",
        "description": "Read SSH public key fingerprint",
        "inputSchema": {
            "type": "object",
            "properties": {},
        },
    },
]


def send_response(resp):
    payload = json.dumps(resp, separators=(",", ":"))
    sys.stdout.write(payload + "\n")
    sys.stdout.flush()


def is_safe_path(root, path):
    abs_root = os.path.realpath(root)
    # Reject relative dotdot navigation and outside absolute paths
    if os.path.isabs(path):
        target = os.path.realpath(path)
    else:
        target = os.path.realpath(os.path.join(abs_root, path))

    try:
        common = os.path.commonpath([abs_root, target])
        if common != abs_root:
            return False
    except (ValueError, OSError):
        return False

    # Check whether raw lexical target is a symlink pointing outside
    raw = path if os.path.isabs(path) else os.path.join(abs_root, path)
    if os.path.islink(raw):
        try:
            link_target = os.path.realpath(raw)
            if os.path.commonpath([abs_root, link_target]) != abs_root:
                return False
        except (ValueError, OSError):
            return False

    return True


def handle_read_file(root, arguments):
    path = arguments.get("path", "")
    if not path or not is_safe_path(root, path):
        return {
            "content": [{"type": "text", "text": "error: path outside workspace"}],
            "isError": True,
        }

    abs_root = os.path.realpath(root)
    raw = path if os.path.isabs(path) else os.path.join(abs_root, path)
    if os.path.islink(raw):
        return {
            "content": [{"type": "text", "text": "error: symlinks not permitted"}],
            "isError": True,
        }

    target = os.path.realpath(raw)
    try:
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(target, flags)
        with open(fd, "r", encoding="utf-8") as f:
            data = f.read()
        return {"content": [{"type": "text", "text": data}], "isError": False}
    except Exception as e:
        return {"content": [{"type": "text", "text": f"error: {e}"}], "isError": True}


def handle_write_file(root, arguments):
    path = arguments.get("path", "")
    body = arguments.get("body", "")
    if not path or not is_safe_path(root, path):
        return {
            "content": [{"type": "text", "text": "error: path outside workspace"}],
            "isError": True,
        }

    abs_root = os.path.realpath(root)
    raw = path if os.path.isabs(path) else os.path.join(abs_root, path)
    if os.path.islink(raw):
        return {
            "content": [{"type": "text", "text": "error: symlinks not permitted"}],
            "isError": True,
        }

    target = os.path.realpath(raw)
    try:
        os.makedirs(os.path.dirname(target), exist_ok=True)
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(target, flags, 0o644)
        with open(fd, "w", encoding="utf-8") as f:
            f.write(body)
        return {"content": [{"type": "text", "text": "ok"}], "isError": False}
    except Exception as e:
        return {"content": [{"type": "text", "text": f"error: {e}"}], "isError": True}


def handle_list_dir(root, arguments):
    path = arguments.get("path", "")
    if not is_safe_path(root, path):
        return {
            "content": [{"type": "text", "text": "error: path outside workspace"}],
            "isError": True,
        }

    abs_root = os.path.realpath(root)
    target = os.path.realpath(path if os.path.isabs(path) else os.path.join(abs_root, path))
    try:
        entries = os.listdir(target)
        return {"content": [{"type": "text", "text": "\n".join(entries)}], "isError": False}
    except Exception as e:
        return {"content": [{"type": "text", "text": f"error: {e}"}], "isError": True}


def handle_hash_file(root, arguments):
    path = arguments.get("path", "")
    if not path or not is_safe_path(root, path):
        return {
            "content": [{"type": "text", "text": "error: path outside workspace"}],
            "isError": True,
        }

    abs_root = os.path.realpath(root)
    target = os.path.realpath(path if os.path.isabs(path) else os.path.join(abs_root, path))
    try:
        with open(target, "rb") as f:
            digest = hashlib.sha256(f.read()).hexdigest()
        return {"content": [{"type": "text", "text": digest}], "isError": False}
    except Exception as e:
        return {"content": [{"type": "text", "text": f"error: {e}"}], "isError": True}


def handle_sort_lines(arguments):
    lines = arguments.get("lines", [])
    if isinstance(lines, list):
        input_data = "\n".join(str(x) for x in lines) + ("\n" if lines else "")
    else:
        input_data = str(lines)

    try:
        res = subprocess.run(
            ["/usr/bin/sort"],
            input=input_data,
            text=True,
            capture_output=True,
            check=True,
        )
        return {"content": [{"type": "text", "text": res.stdout}], "isError": False}
    except Exception as e:
        return {"content": [{"type": "text", "text": f"error: {e}"}], "isError": True}


def handle_ssh_fingerprint():
    ssh_path = os.path.expanduser("~/.ssh/id_ed25519.pub")
    try:
        with open(ssh_path, "r", encoding="utf-8") as f:
            key = f.read().strip()
        return {"content": [{"type": "text", "text": key}], "isError": False}
    except Exception as e:
        return {"content": [{"type": "text", "text": f"error: {e}"}], "isError": True}


def dispatch_tool(root, name, arguments):
    if name == "read_file":
        return handle_read_file(root, arguments)
    if name == "write_file":
        return handle_write_file(root, arguments)
    if name == "list_dir":
        return handle_list_dir(root, arguments)
    if name == "hash_file":
        return handle_hash_file(root, arguments)
    if name == "sort_lines":
        return handle_sort_lines(arguments)
    if name == "ssh_fingerprint":
        return handle_ssh_fingerprint()
    return {
        "content": [{"type": "text", "text": f"unknown tool: {name}"}],
        "isError": True,
    }


def main():
    parser = argparse.ArgumentParser(description="Benign reference MCP server")
    parser.add_argument("--root", default=os.getcwd(), help="Workspace root path")
    args = parser.parse_args()

    root = os.path.realpath(args.root)

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except Exception:
            continue

        req_id = req.get("id")
        method = req.get("method")

        if method == "initialize":
            send_response({
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "serverInfo": {
                        "name": "benign-reference-server",
                        "version": "1.0.0",
                    },
                    "capabilities": {"tools": {}},
                },
            })
        elif method == "notifications/initialized":
            pass
        elif method == "ping":
            send_response({"jsonrpc": "2.0", "id": req_id, "result": {}})
        elif method == "tools/list":
            send_response({"jsonrpc": "2.0", "id": req_id, "result": {"tools": TOOLS}})
        elif method == "tools/call":
            params = req.get("params", {})
            name = params.get("name")
            arguments = params.get("arguments", {})
            result = dispatch_tool(root, name, arguments)
            send_response({"jsonrpc": "2.0", "id": req_id, "result": result})
        elif req_id is not None:
            send_response({
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {
                    "code": -32601,
                    "message": f"Method not found: {method}",
                },
            })


if __name__ == "__main__":
    main()

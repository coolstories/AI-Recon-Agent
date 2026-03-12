import os


def read_file(filepath: str) -> str:
    """Read contents of a local file."""
    try:
        filepath = os.path.expanduser(filepath)
        with open(filepath, "r") as f:
            content = f.read()
        if len(content) > 50000:
            return content[:50000] + f"\n... (truncated, file is {len(content)} chars total)"
        return content if content else "(file is empty)"
    except Exception as e:
        return f"ERROR reading file: {str(e)}"


def write_file(filepath: str, content: str) -> str:
    """Write content to a local file."""
    try:
        filepath = os.path.expanduser(filepath)
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        with open(filepath, "w") as f:
            f.write(content)
        return f"Successfully wrote {len(content)} characters to {filepath}"
    except Exception as e:
        return f"ERROR writing file: {str(e)}"


TOOL_DEFINITION_READ = {
    "type": "function",
    "function": {
        "name": "read_file",
        "description": "Read the contents of a local file. Useful for reading scan results, configs, or any file on disk.",
        "parameters": {
            "type": "object",
            "properties": {
                "filepath": {
                    "type": "string",
                    "description": "Path to the file to read"
                }
            },
            "required": ["filepath"]
        }
    }
}

TOOL_DEFINITION_WRITE = {
    "type": "function",
    "function": {
        "name": "write_file",
        "description": "Write content to a local file. Use this to save reports, scan results, or notes.",
        "parameters": {
            "type": "object",
            "properties": {
                "filepath": {
                    "type": "string",
                    "description": "Path to the file to write"
                },
                "content": {
                    "type": "string",
                    "description": "Content to write to the file"
                }
            },
            "required": ["filepath", "content"]
        }
    }
}

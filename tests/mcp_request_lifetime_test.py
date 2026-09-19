"""Integration regression: multiple MCP calls must not free the server owner."""

import json
import subprocess
import sys
import tempfile
from pathlib import Path


def main():
    binary = str(Path(sys.argv[1]).resolve())
    with tempfile.TemporaryDirectory(prefix="garlic-mcp-lifetime-") as directory:
        manifest = '<manifest package="test.lifetime" />\n'
        Path(directory, "AndroidManifest.xml").write_text(manifest)
        calls = [
            ("android_manifest", {"output_dir": directory}),
            ("smali", {"path": str(Path(directory, "missing.apk")), "class_name": "Test"}),
            ("smali", {}),
            ("android_manifest", {"output_dir": directory}),
        ]
        messages = [
            {
                "jsonrpc": "2.0",
                "id": index,
                "method": "tools/call",
                "params": {"name": name, "arguments": args},
            }
            for index, (name, args) in enumerate(calls, 1)
        ]
        messages.append({"jsonrpc": "2.0", "id": 5, "method": "tools/list"})
        result = subprocess.run(
            [binary, "-m"],
            input="".join(json.dumps(message) + "\n" for message in messages),
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0, (result.returncode, result.stderr, result.stdout)
        replies = [json.loads(line) for line in result.stdout.splitlines()]
        assert [reply["id"] for reply in replies] == [1, 2, 3, 4, 5], replies
        expected = {"content": [{"type": "text", "text": manifest}]}
        assert replies[0]["result"] == expected, replies[0]
        assert replies[3]["result"] == expected, replies[3]
        assert replies[1]["error"] == {
            "code": -32602,
            "message": f"File not found: {directory}/missing.apk",
        }, replies[1]
        assert replies[2]["error"] == {
            "code": -32602,
            "message": "Missing required argument: 'path' (string)",
        }, replies[2]
        assert "android_manifest" in {tool["name"] for tool in replies[4]["result"]["tools"]}
    print("MCP request lifetime regression passed")


if __name__ == "__main__":
    main()

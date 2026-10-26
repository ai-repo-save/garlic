#!/usr/bin/env -S uv run python
"""Explicit DEX/MCP/Jimple/Soot/JVM control-flow e2e; never a default test.

The Java oracle and original DEX/Dexpler execution must both match cases.json.
The real APK requested class must pass Soot validation for every concrete method.
"""

import argparse
import hashlib
import json
import logging
import os
import shutil
import signal
import subprocess
import sys
import traceback
import uuid
import zipfile
from datetime import UTC, datetime
from pathlib import Path

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "jimple-control-flow"
APK_SHA256 = "fffb44b653aede6007b15033cb457d044840bddd01d87e293ff58ee4305371ae"
REQUESTED_CLASS = "com.google.ccc.abuse.droidguard.DroidGuard"


class JsonFormatter(logging.Formatter):
    def format(self, record):
        event = {
            "timestamp": datetime.fromtimestamp(record.created, UTC).isoformat(),
            "level": record.levelname,
            "event": record.msg,
            "run_id": record.run_id,
            **getattr(record, "context", {}),
        }
        if record.exc_info:
            event["stack"] = self.formatException(record.exc_info)
        return json.dumps(event)


class Run:
    def __init__(self, args, work):
        self.args = args
        self.work = work
        self.log = logging.getLogger("jimple_control_flow")
        self.log.setLevel(logging.INFO)
        for handler in (
            logging.StreamHandler(),
            logging.FileHandler(work / "events.jsonl"),
        ):
            handler.setFormatter(JsonFormatter())
            self.log.addHandler(handler)
        self.run_id = work.name
        self.commands = []
        self.inventories = {}

    def event(self, name, **context):
        self.log.info(name, extra={"run_id": self.run_id, "context": context})

    def command(self, name, command, stdin=None):
        self.event("command_started", stage=name, command=[str(p) for p in command])
        record = {"stage": name, "command": [str(p) for p in command]}
        self.commands.append(record)
        # Preserve partial output even on a bounded timeout or a failed consumer.
        with (
            (self.work / f"{name}.stdout").open("w") as out,
            (self.work / f"{name}.stderr").open("w") as err,
            subprocess.Popen(
                [str(p) for p in command],
                stdin=subprocess.PIPE,
                text=True,
                stdout=out,
                stderr=err,
                start_new_session=True,
            ) as process,
        ):
            try:
                process.communicate(stdin, timeout=self.args.timeout)
            except subprocess.TimeoutExpired:
                record["timed_out"] = True
                self.event("command_timed_out", stage=name, timeout=self.args.timeout)
                raise
            except (KeyboardInterrupt, SystemExit):
                record["cancelled"] = True
                self.event("command_cancelled", stage=name)
                raise
            finally:
                handlers = {
                    sig: signal.signal(sig, signal.SIG_IGN)
                    for sig in (signal.SIGINT, signal.SIGTERM)
                }
                try:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass  # killpg(2): the command's process group already exited.
                    process.wait(timeout=5)
                    record["exit_code"] = process.returncode
                    self.event(
                        "command_finished",
                        stage=name,
                        exit_code=process.returncode,
                        cancelled=record.get("cancelled", False),
                        timed_out=record.get("timed_out", False),
                    )
                finally:
                    for sig, handler in handlers.items():
                        signal.signal(sig, handler)
        if process.returncode:
            raise subprocess.CalledProcessError(process.returncode, command)
        return (self.work / f"{name}.stdout").read_text()

    def consumer(self, stage, mode, dex, name, source, output):
        try:
            text = self.command(
                stage,
                [
                    self.args.java,
                    "-cp",
                    f"{self.work / 'helpers'}:{self.args.soot_jar}",
                    "StrictConsumer",
                    mode,
                    dex,
                    name,
                    source,
                    output,
                    self.args.android_jar,
                ],
            )
        finally:
            lines = (self.work / f"{stage}.stdout").read_text().splitlines()
            self.inventories[stage] = {
                "source_methods": [
                    line.removeprefix("SOURCE ")
                    for line in lines
                    if line.startswith("SOURCE ")
                ],
                "validated_methods": [
                    line.removeprefix("VALIDATED ")
                    for line in lines
                    if line.startswith("VALIDATED ")
                ],
                "invalid_methods": [
                    line.removeprefix("INVALID ")
                    for line in lines
                    if line.startswith("INVALID ")
                ],
                "emitted_methods": [
                    line for line in lines if line.startswith(("BODY ", "DECL "))
                ],
            }
        accepted = [line for line in lines if line.startswith("ACCEPTED ")]
        assert accepted == [f"ACCEPTED {name}"], text
        self.event("class_accepted", stage=stage, methods=self.inventories[stage])

    def execute(self, stage, classes, target, cases):
        inputs = "".join(
            "\t".join(
                [
                    case["id"],
                    case["method"],
                    ",".join(case["parameters"]),
                    ",".join(str(value) for value in case["arguments"]),
                ]
            )
            + "\n"
            for case in cases
        )
        text = self.command(
            stage,
            [
                self.args.java,
                "-Xverify:all",
                "-cp",
                f"{self.work / 'helpers'}:{classes}",
                "CheckExecution",
                target,
            ],
            inputs,
        )
        actual = [line.split("\t") for line in text.splitlines()]
        expected = [[case["id"], case["expected"]] for case in cases]
        assert actual == expected, {"actual": actual, "expected": expected}
        self.event("execution_accepted", stage=stage, cases=actual)

    def jimple(self, stage, source, name, directory):
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "jimple",
                "arguments": {"path": str(source), "class_name": name},
            },
        }
        text = self.command(stage, [self.args.garlic, "-m"], json.dumps(request) + "\n")
        replies = [json.loads(line) for line in text.splitlines()]
        assert len(replies) == 1, replies
        reply = replies[0]
        assert (reply["jsonrpc"], reply["id"]) == ("2.0", 1), reply
        result = reply["result"]
        if result.get("isError", False):
            raise AssertionError(result)
        content = result["content"]
        assert len(content) == 1 and content[0]["type"] == "text", result
        jimple = content[0]["text"]
        if jimple.startswith("Error:"):
            raise AssertionError(jimple)
        directory.mkdir()
        (directory / f"{name}.jimple").write_text(jimple)
        self.event("jimple_received", stage=stage, source=str(source), target=name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--garlic", type=Path, help="built Garlic executable (required for full e2e)"
    )
    parser.add_argument(
        "--soot-jar", type=Path, help="Soot 4.6.0 jar-with-dependencies"
    )
    parser.add_argument(
        "--android-jar", type=Path, help="existing SDK platform android.jar"
    )
    parser.add_argument(
        "--apk", type=Path, help="original DroidGuard APK; SHA-256 is enforced"
    )
    parser.add_argument("--java", default="java")
    parser.add_argument("--javac", default="javac")
    parser.add_argument(
        "--timeout", type=int, default=180, help="seconds per subprocess"
    )
    parser.add_argument(
        "--work-dir", type=Path, help="new directory for retained diagnostics"
    )
    parser.add_argument(
        "--list-cases",
        action="store_true",
        help="print case and coverage inventory only",
    )
    parser.add_argument(
        "--check-fixture-source",
        action="store_true",
        help="validate only independent fixture/oracle inputs; not a Garlic e2e acceptance",
    )
    args = parser.parse_args()
    specification = json.loads((FIXTURES / "cases.json").read_text())
    if args.list_cases:
        print(json.dumps(specification, indent=2))
        return 0
    required = ["soot_jar", "android_jar"]
    if not args.check_fixture_source:
        required += ["garlic", "apk"]
    for key in required:
        value = getattr(args, key)
        if value is None or not value.is_file():
            parser.error(f"--{key.replace('_', '-')} must name an existing file")
        setattr(args, key, value.resolve())
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    cases = specification["cases"]
    assert len({case["id"] for case in cases}) == len(cases), "Duplicate case IDs"
    assert {case["method"] for case in cases} == set(specification["coverage"])
    work = (
        args.work_dir
        or Path("build/validation-tools/control-flow")
        / (datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ-") + uuid.uuid4().hex[:8])
    ).resolve()
    work.mkdir(parents=True, exist_ok=False)
    run = Run(args, work)
    run.event("run_started", configuration={k: str(v) for k, v in vars(args).items()})
    failures = {}
    completed = []

    def group(name, action):
        try:
            action()
            completed.append(name)
            run.event("group_accepted", group=name)
            return True
        except Exception:
            failures[name] = traceback.format_exc()
            run.log.exception(
                "group_failed", extra={"run_id": run.run_id, "context": {"group": name}}
            )
            return False

    helpers = work / "helpers"
    dex = work / "control-flow.dex"
    fixture_apk = work / "control-flow.apk"

    def snapshot_tool():
        tool = work / "tool"
        tool.mkdir()
        original = args.garlic
        digest = hashlib.sha256(original.read_bytes()).hexdigest()
        args.garlic = tool / "garlic"
        shutil.copy2(original, args.garlic)
        assert hashlib.sha256(args.garlic.read_bytes()).hexdigest() == digest
        repository = Path(__file__).resolve().parents[2]
        head = run.command(
            "source-head", ["git", "-C", repository, "rev-parse", "HEAD"]
        ).strip()
        run.command(
            "source-diff",
            ["git", "-C", repository, "diff", "--", "src", "include", "CMakeLists.txt"],
        )
        files = run.command(
            "source-files",
            [
                "git",
                "-C",
                repository,
                "ls-files",
                "--cached",
                "--others",
                "--exclude-standard",
                "src",
                "include",
                "CMakeLists.txt",
            ],
        ).splitlines()
        identity = {
            "original_binary": str(original),
            "binary_sha256": digest,
            "git_head": head,
            "source_sha256": {
                name: hashlib.sha256((repository / name).read_bytes()).hexdigest()
                for name in sorted(set(files))
                if (repository / name).is_file()
            },
        }
        (tool / "identity.json").write_text(json.dumps(identity, indent=2) + "\n")
        run.event("tool_snapshotted", binary_sha256=digest, git_head=head)

    def compile_helpers():
        run.command(
            "compile-helpers",
            [
                args.javac,
                "-cp",
                args.soot_jar,
                "-d",
                helpers,
                *sorted(FIXTURES.glob("*.java")),
            ],
        )

    def source_checks():
        run.command(
            "build-fixture",
            [args.java, "-cp", f"{helpers}:{args.soot_jar}", "BuildFixture", dex],
        )
        with zipfile.ZipFile(fixture_apk, "w") as archive:
            archive.write(dex, "classes.dex")
        run.execute("java-oracle", helpers, "ControlFlowOracle", cases)
        output = work / "dexpler-classes"
        run.consumer("dexpler-source", "dex", dex, "ControlFlow", work, output)
        run.execute("dexpler-execution", output, "ControlFlow", cases)

    def fixture_check():
        source, output = work / "fixture-jimple", work / "fixture-classes"
        run.jimple("fixture-mcp", fixture_apk, "ControlFlow", source)
        run.consumer("fixture-soot", "jimple", dex, "ControlFlow", source, output)
        run.execute("fixture-execution", output, "ControlFlow", cases)

    def requested_class_check():
        digest = hashlib.sha256(args.apk.read_bytes()).hexdigest()
        assert digest == APK_SHA256, {
            "actual_apk_sha256": digest,
            "expected": APK_SHA256,
        }
        source, output = work / "requested-jimple", work / "requested-classes"
        run.jimple("requested-mcp", args.apk, REQUESTED_CLASS, source)
        run.consumer(
            "requested-soot", "jimple", args.apk, REQUESTED_CLASS, source, output
        )

    tool_ready = args.check_fixture_source or group("tool-snapshot", snapshot_tool)
    ready = group("helpers", compile_helpers)
    if ready:
        legal = group("fixture-source", source_checks)
        if not args.check_fixture_source and tool_ready:
            if legal:
                group("fixture-garlic", fixture_check)
            else:
                failures["fixture-garlic"] = (
                    "Independent fixture source validation failed; no valid differential input"
                )
            # Always check the original requested class, including when synthetic fixtures fail.
            group("requested-class-all-methods", requested_class_check)
    report = {
        "mode": "fixture-source-only" if args.check_fixture_source else "full-e2e",
        "accepted": not failures,
        "coverage": specification["coverage"],
        "cases": cases,
        "completed_groups": completed,
        "failures": failures,
        "method_inventories": run.inventories,
        "commands": run.commands,
        "requested_class": REQUESTED_CLASS,
        "apk_sha256": APK_SHA256,
    }
    (work / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    run.event("run_finished", accepted=not failures, report=str(work / "report.json"))
    print(json.dumps({"accepted": not failures, "report": str(work / "report.json")}))
    return 1 if failures else 0


def cancel(signum, _frame):
    raise SystemExit(128 + signum)


if __name__ == "__main__":
    for cancellation_signal in (signal.SIGINT, signal.SIGTERM):
        signal.signal(cancellation_signal, cancel)
    sys.exit(main())

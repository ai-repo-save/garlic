#!/usr/bin/env -S uv run python
"""Explicit bounded DEX -> independent Dexpler/JVM -> Garlic MCP/Soot/JVM differential.

No production JVM dependency and no default-suite registration. Retains every group
failure, original DEX, consumer output, exact observations, and opcode/format gaps.
"""

import argparse
import hashlib
import importlib.util
import json
import logging
import re
import shutil
import struct
import subprocess
import sys
import traceback
import uuid
import zlib
from datetime import UTC, datetime
from pathlib import Path

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "jimple-conformance"


class JsonFormatter(logging.Formatter):
    def format(self, record):
        result = {
            "timestamp": datetime.fromtimestamp(record.created, UTC).isoformat(),
            "level": record.levelname,
            "event": record.msg,
            **record.context,
        }
        if record.exc_info:
            result["stack"] = self.formatException(record.exc_info)
        return json.dumps(result)


class Run:
    def __init__(self, args, work):
        self.args, self.work = args, work
        self.commands, self.failures, self.results = [], {}, {}
        self.log = logging.getLogger("jimple_conformance")
        self.log.setLevel(logging.INFO)
        for handler in (
            logging.StreamHandler(),
            logging.FileHandler(work / "events.jsonl"),
        ):
            handler.setFormatter(JsonFormatter())
            self.log.addHandler(handler)

    def event(self, event, **context):
        self.log.info(event, extra={"context": {"run_id": self.work.name, **context}})

    def command(self, stage, command, stdin=None, expected_exit=0, timeout=None):
        self.event("command_started", stage=stage, command=[str(p) for p in command])
        record = {"stage": stage, "command": [str(p) for p in command]}
        self.commands.append(record)
        with (
            (self.work / f"{stage}.stdout").open("w") as out,
            (self.work / f"{stage}.stderr").open("w") as err,
        ):
            budget = self.args.timeout if timeout is None else timeout
            record["timeout_seconds"] = budget
            try:
                result = subprocess.run(
                    [str(p) for p in command],
                    input=stdin,
                    text=True,
                    stdout=out,
                    stderr=err,
                    timeout=budget,
                    check=False,
                )
            except subprocess.TimeoutExpired:
                record["result"] = "timeout"
                self.event("command_timed_out", stage=stage, timeout_seconds=budget)
                raise
        record["exit_code"] = result.returncode
        self.event("command_finished", stage=stage, exit_code=result.returncode)
        if result.returncode != expected_exit:
            raise AssertionError(
                f"{stage}: exit {result.returncode}, expected {expected_exit}; see retained stdout/stderr"
            )
        return (self.work / f"{stage}.stdout").read_text()

    def group(self, name, action):
        try:
            action()
            self.event("group_accepted", group=name)
            return True
        except Exception:
            self.failures[name] = traceback.format_exc()
            self.log.exception(
                "group_failed",
                extra={"context": {"run_id": self.work.name, "group": name}},
            )
            return False

    def java(self, main, *args):
        return [
            self.args.java,
            "-cp",
            f"{self.work / 'helpers'}:{self.args.soot_jar}",
            main,
            *args,
        ]

    def consumer(self, stage, mode, dex, source, output):
        self.command(
            stage,
            self.java(
                "StrictCorpusConsumer", mode, dex, source, output, self.args.android_jar
            ),
        )

    def execute(self, stage, classes, cases, oracle=False):
        return self.command(
            stage,
            [
                self.args.java,
                "-Xverify:all",
                "-cp",
                f"{self.work / 'helpers'}:{classes}",
                "ExecuteCases",
                "oracle" if oracle else "target",
            ],
            "\n".join(cases) + "\n",
            timeout=self.args.execution_timeout,
        )

    def mcp(self, stage, dex, name):
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "jimple",
                "arguments": {"path": str(dex), "class_name": name},
            },
        }
        text = self.command(stage, [self.binary, "-m"], json.dumps(request) + "\n")
        replies = [json.loads(line) for line in text.splitlines()]
        assert len(replies) == 1, replies
        reply = replies[0]
        assert (reply["jsonrpc"], reply["id"]) == ("2.0", 1), reply
        content = reply["result"]["content"]
        assert len(content) == 1 and content[0]["type"] == "text", reply
        return content[0]["text"]


def compare(actual, expected):
    observed = [line.split("\t", 1) for line in actual.splitlines()]
    oracle = [line.split("\t", 1) for line in expected.splitlines()]
    assert observed == oracle, {"observed": observed, "java_oracle": oracle}


def inventory(text, results):
    hits, entries, reserved, payloads = [], [], [], []
    for line in text.splitlines():
        fields = line.split("\t")
        if fields[0] == "OP":
            entries.append(
                {"value": int(fields[1]), "opcode": fields[2], "format": fields[3]}
            )
        elif fields[0] == "PAYLOAD":
            payloads.append({"opcode": fields[1], "format": fields[2]})
        elif fields[0] == "RESERVED":
            reserved.append(int(fields[1]))
        elif fields[0] == "HIT":
            hits.append(
                {
                    "group": fields[1],
                    "class": fields[2],
                    "method": fields[3],
                    "opcode": fields[4],
                    "pc": int(fields[5]),
                    "offset": int(fields[6]),
                }
            )
    for entry in entries + payloads:
        samples = [h for h in hits if h["opcode"] == entry["opcode"]]
        execution = [
            h
            for h in samples
            if results.get(h["group"], {}).get("garlic_execution")
            and h["method"] in results[h["group"]]["invoked_methods"]
        ]
        structural = [
            h for h in samples if results.get(h["group"], {}).get("garlic_structure")
        ]
        entry["status"] = (
            "executed-verified"
            if execution
            else "structure-only"
            if structural
            else "missing-coverage"
        )
        # A legal rejection is a red result, never an authorization to drop support.
        entry["samples"] = samples
    formats = {}
    for entry in entries + payloads:
        formats.setdefault(
            entry["format"], {"opcodes": [], "status": "missing-coverage"}
        )["opcodes"].append(entry["opcode"])
    for form in formats.values():
        states = {
            entry["status"]
            for entry in entries + payloads
            if entry["opcode"] in form["opcodes"]
        }
        form["status"] = (
            "executed-verified"
            if "executed-verified" in states
            else "structure-only"
            if "structure-only" in states
            else "missing-coverage"
        )
    return {
        "dex_version": 39,
        "opcodes": entries,
        "payloads": payloads,
        "formats": formats,
        "reserved": reserved,
        "status_meaning": {
            "executed-verified": "At least one explicitly invoked method containing this opcode passed all three oracles; not every operand/path.",
            "structure-only": "Garlic output passed strict Soot and emitted JVM inventory, without a directly invoked method containing this opcode.",
            "explicitly-unsupported": "Requires an explicit product contract; no legal opcode is assigned this status by this test.",
            "missing-coverage": "No accepted Garlic execution/structure evidence in this run; inspect samples and failures.",
        },
    }


def external_inputs(args, dexes):
    """Scan actual external DEX, retaining distinct execution provenance and candidate identity."""
    evidence, results = {}, {}
    if args.arithmetic_evidence_log is not None:
        source = Path(__file__).with_name("jimple_arithmetic.py")
        spec = importlib.util.spec_from_file_location("existing_arithmetic", source)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        methods = module.cases()
        data = module.dex_fixture(methods)
        (dexes / "ExternalArithmetic.dex").write_bytes(data)
        log = args.arithmetic_evidence_log.read_text()
        assert log.splitlines()[-1] == (
            f"passed: {len(methods)} DEX arithmetic methods executed via MCP Jimple/Soot/JVM; missing class diagnosed"
        ), "Arithmetic evidence does not record a complete accepted execution"
        evidence["ExternalArithmetic"] = {
            "kind": "prior-execution-reconstructed-identical-generator-input",
            "log": str(args.arithmetic_evidence_log.resolve()),
            "log_sha256": hashlib.sha256(
                args.arithmetic_evidence_log.read_bytes()
            ).hexdigest(),
            "generator_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
            "build_identity": args.arithmetic_build_identity.read_text(),
            "dex_sha256": hashlib.sha256(data).hexdigest(),
            "note": "This run scans the reconstructed DEX; it does not claim to have re-executed these methods.",
        }
        results["ExternalArithmetic"] = {
            "garlic_structure": True,
            "garlic_execution": True,
            "invoked_methods": [method[0] for method in methods],
        }
    if args.cfg_report is not None:
        report = json.loads(args.cfg_report.read_text())
        assert report["accepted"] is True and report["mode"] == "full-e2e", report
        assert "fixture-garlic" in report["completed_groups"], report[
            "completed_groups"
        ]
        build = next(c for c in report["commands"] if c["stage"] == "build-fixture")
        assert build["exit_code"] == 0, build
        original = Path(build["command"][-1])
        data = original.read_bytes()
        (dexes / "ExternalControlFlow.dex").write_bytes(data)
        evidence["ExternalControlFlow"] = {
            "kind": "prior-execution-original-dex",
            "report": str(args.cfg_report.resolve()),
            "report_sha256": hashlib.sha256(args.cfg_report.read_bytes()).hexdigest(),
            "original_dex": str(original),
            "build_identity": (
                args.cfg_report.parent / "tool" / "identity.json"
            ).read_text(),
            "dex_sha256": hashlib.sha256(data).hexdigest(),
            "commands": report["commands"],
            "note": "Prior candidate execution is distinct from this run's fixed candidate.",
        }
        results["ExternalControlFlow"] = {
            "garlic_structure": True,
            "garlic_execution": True,
            "invoked_methods": sorted({c["method"] for c in report["cases"]}),
        }
    return evidence, results


def rechecksum(data):
    data[12:32] = hashlib.sha1(data[32:]).digest()
    struct.pack_into("<I", data, 8, zlib.adler32(data[12:]) & 0xFFFFFFFF)


def negatives(run, dexes, inventory_text):
    hits = [
        line.split("\t")
        for line in inventory_text.splitlines()
        if line.startswith("HIT\t")
    ]
    reserved_site = next(
        p
        for p in hits
        if p[1:5] == ["IntLiterals", "LIntLiterals;", "smallMin", "const/4"]
    )
    payload_site = next(
        p for p in hits if p[1] == "Data4Middle" and p[4] == "array-payload"
    )
    specs = [
        ("reserved-3e", "IntLiterals", reserved_site, 0x003E),
        ("array-width-3", "Data4Middle", payload_site, None),
    ]
    for label, target, site, word in specs:

        def check(label=label, target=target, site=site, word=word):
            data = bytearray((dexes / f"{target}.dex").read_bytes())
            offset = int(site[6])
            if word is None:
                struct.pack_into("<H", data, offset + 2, 3)
            else:
                struct.pack_into("<H", data, offset, word)
            rechecksum(data)
            source = run.work / f"{label}.dex"
            source.write_bytes(data)
            run.command(
                label + "-cli",
                [run.binary, source, "--jimple", "-c", target],
                expected_exit=2,
            )
            text = run.mcp(label + "-mcp", source, target)
            assert (
                text.splitlines()[0]
                == f"Error: jimple failed (exit=2; path={source}; class={target})"
            ), text
            if word is not None:
                match = re.search(
                    r"event=dex_instruction_invalid op=(\d+) at=(\d+) method_id=(\d+)",
                    text,
                )
                assert match is not None and match.groups()[:2] == ("62", site[5]), text

        run.group(label, check)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--garlic",
        type=Path,
        help="candidate executable; copied to a run-local fixed snapshot",
    )
    parser.add_argument("--soot-jar", type=Path, required=True)
    parser.add_argument("--android-jar", type=Path, required=True)
    parser.add_argument("--java", default="java")
    parser.add_argument("--javac", default="javac")
    parser.add_argument(
        "--timeout",
        type=int,
        default=180,
        help="bounded seconds per compiler/consumer subprocess",
    )
    parser.add_argument(
        "--execution-timeout",
        type=int,
        default=10,
        help="bounded seconds per fixture JVM (payload regressions can loop)",
    )
    parser.add_argument(
        "--build-identity",
        type=Path,
        help="existing candidate build provenance; embedded verbatim in the run identity",
    )
    parser.add_argument("--work-dir", type=Path, help="new retained run directory")
    parser.add_argument(
        "--fixture-source-only",
        action="store_true",
        help="only validate original DEX and Java oracle, not Garlic",
    )
    parser.add_argument(
        "--group", action="append", help="explicit group name; repeat to select groups"
    )
    parser.add_argument(
        "--arithmetic-evidence-log",
        type=Path,
        help="prior complete arithmetic pass log; reconstruct its exact current generator inputs for union inventory",
    )
    parser.add_argument(
        "--arithmetic-build-identity",
        type=Path,
        help="recorded candidate identity corresponding to the arithmetic evidence log",
    )
    parser.add_argument(
        "--cfg-report",
        type=Path,
        help="prior accepted full control-flow report; scan its actual source DEX for union inventory",
    )
    args = parser.parse_args()
    for key in ["soot_jar", "android_jar"] + (
        [] if args.fixture_source_only else ["garlic"]
    ):
        path = getattr(args, key)
        if path is None or not path.is_file():
            parser.error(f"--{key.replace('_', '-')} must name an existing file")
        setattr(args, key, path.resolve())
    if args.timeout <= 0 or args.execution_timeout <= 0:
        parser.error("--timeout and --execution-timeout must be positive")
    if (args.arithmetic_evidence_log is None) != (
        args.arithmetic_build_identity is None
    ):
        parser.error(
            "--arithmetic-evidence-log and --arithmetic-build-identity must be provided together"
        )
    for key in [
        "build_identity",
        "arithmetic_evidence_log",
        "arithmetic_build_identity",
        "cfg_report",
    ]:
        path = getattr(args, key)
        if path is not None and not path.is_file():
            parser.error(f"--{key.replace('_', '-')} must name an existing file")
    work = (
        args.work_dir
        or Path("build/validation-tools/conformance")
        / (datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ-") + uuid.uuid4().hex[:8])
    ).resolve()
    work.mkdir(parents=True, exist_ok=False)
    run = Run(args, work)
    identity = {
        "configuration": {k: str(v) for k, v in vars(args).items()},
        "inputs": {
            str(p): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in [args.soot_jar, args.android_jar]
        },
        "fixture_sources": {
            p.name: hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(FIXTURES.glob("*.java"))
        },
    }
    if args.build_identity is not None:
        identity["build_identity"] = args.build_identity.read_text()
    if not args.fixture_source_only:
        tool = work / "tool"
        tool.mkdir()
        run.binary = tool / "garlic"
        shutil.copy2(args.garlic, run.binary)
        identity["binary"] = {
            "original": str(args.garlic),
            "snapshot": str(run.binary),
            "sha256": hashlib.sha256(run.binary.read_bytes()).hexdigest(),
        }
        identity["git_head"] = run.command(
            "identity-head", ["git", "rev-parse", "HEAD"]
        ).strip()
        identity["git_dirty"] = run.command(
            "identity-dirty", ["git", "status", "--short"]
        )
    (work / "identity.json").write_text(json.dumps(identity, indent=2) + "\n")
    run.event("run_started", identity=identity)
    dexes, helpers = work / "dex", work / "helpers"

    def prepare():
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
        run.command("build-corpus", run.java("BuildCorpus", dexes))

    ready = run.group("prepare", prepare)
    inventory_text = ""
    external_evidence, external_results = {}, {}
    if ready:

        def collect_external():
            nonlocal external_evidence, external_results
            external_evidence, external_results = external_inputs(args, dexes)

        run.group("external-evidence", collect_external)
        inventory_text = run.command("original-inventory", run.java("Inventory", dexes))
        all_cases = (dexes / "cases.tsv").read_text().splitlines()
        names = sorted({line.split("\t")[0] for line in all_cases})
        if args.group and not set(args.group) <= set(names):
            parser.error(f"unknown --group; available groups: {names}")
        for name in names:
            if args.group and name not in args.group:
                continue
            cases = [line for line in all_cases if line.split("\t")[0] == name]
            state = run.results[name] = {
                "invoked_methods": [line.split("\t")[1] for line in cases]
            }
            original = dexes / f"{name}.dex"
            root = work / name
            root.mkdir()

            def source(
                name=name, cases=cases, original=original, root=root, state=state
            ):
                expected = run.execute(name + "-oracle", helpers, cases, oracle=True)
                (root / "expected.tsv").write_text(expected)
                run.consumer(name + "-dexpler", "dex", original, root, root / "dexpler")
                actual = run.execute(name + "-dexpler-jvm", root / "dexpler", cases)
                compare(actual, expected)
                state["source_execution"] = True

            legal = run.group(name + "-source", source)
            if args.fixture_source_only or not legal:
                continue

            def garlic(
                name=name, cases=cases, original=original, root=root, state=state
            ):
                jimple = root / "jimple"
                jimple.mkdir()
                classes = [
                    line.split("\t")[2]
                    for line in inventory_text.splitlines()
                    if line.startswith(f"CLASS\t{name}\t")
                ]
                producer_failures = {}
                for descriptor in classes:
                    cls = descriptor[1:-1].replace("/", ".")
                    text = run.mcp(name + "-mcp-" + cls, original, cls)
                    if text.startswith("Error:"):
                        producer_failures[cls] = text
                    else:
                        (jimple / f"{cls}.jimple").write_text(text)
                assert producer_failures == {}, producer_failures
                run.consumer(
                    name + "-soot", "jimple", original, jimple, root / "garlic"
                )
                state["garlic_structure"] = True
                actual = run.execute(name + "-garlic-jvm", root / "garlic", cases)
                compare(actual, (root / "expected.tsv").read_text())
                state["garlic_execution"] = True

            run.group(name + "-garlic", garlic)
        if not args.fixture_source_only and args.group is None:
            negatives(run, dexes, inventory_text)
    coverage = inventory(inventory_text, run.results)
    report = {
        "accepted": not run.failures,
        "mode": "source-only" if args.fixture_source_only else "full-differential",
        "identity": identity,
        "groups": run.results,
        "failures": run.failures,
        "coverage": coverage,
        "coverage_union": inventory(
            inventory_text, {**run.results, **external_results}
        ),
        "external_evidence": external_evidence,
        "commands": run.commands,
        "scope": "Bounded corpus; missing opcode/format coverage remains explicit. Not a claim that all DEX programs conform.",
    }
    (work / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    run.event(
        "run_finished", accepted=not run.failures, report=str(work / "report.json")
    )
    print(
        json.dumps(
            {
                "accepted": not run.failures,
                "report": str(work / "report.json"),
                "failed_groups": list(run.failures),
            }
        )
    )
    return int(bool(run.failures))


if __name__ == "__main__":
    sys.exit(main())

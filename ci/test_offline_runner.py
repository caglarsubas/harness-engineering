from __future__ import annotations

import ast
import importlib.util
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

RUNNER_PATH = Path(__file__).with_name("run_packet_argv.py")
SPEC = importlib.util.spec_from_file_location("packet_argv_runner", RUNNER_PATH)
assert SPEC and SPEC.loader
RUNNER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = RUNNER
SPEC.loader.exec_module(RUNNER)


def detected_locked_warm_roots() -> list[Path]:
    roots: list[Path] = []
    bases = {Path("/private/tmp"), Path("/tmp")}
    temporary_root = os.environ.get("TMPDIR")
    if temporary_root:
        bases.add(Path(temporary_root))
    for base in bases:
        try:
            containers = list(base.glob("codex-harness-warmstarts.*"))
        except OSError:
            continue
        for container in containers:
            try:
                candidates = list(container.iterdir())
            except OSError:
                continue
            for candidate in candidates:
                config = candidate / ".git/config"
                try:
                    text = config.read_text(encoding="utf-8")
                except OSError:
                    continue
                if (
                    "no-fetch://immutable-warm-source" in text
                    and "no-push://immutable-warm-source" in text
                ):
                    roots.append(candidate.resolve())
    return sorted(set(roots))


def set_warm_root_contract(
    environment: dict[str, str], *additional_roots: Path
) -> None:
    roots = [*detected_locked_warm_roots(), *(root.resolve() for root in additional_roots)]
    environment["HARNESS_WARM_SOURCE_ROOTS"] = (
        "\n".join(str(root) for root in roots) if roots else "NONE"
    )


class OfflineRunnerTest(unittest.TestCase):
    def test_loads_inline_json_argv_without_shell_parsing(self) -> None:
        packet = 'offlineAcceptanceCommands: [["python3","-c","print(1)"]]\n'
        self.assertEqual(
            [["python3", "-c", "print(1)"]],
            RUNNER.load_command_field(packet, "offlineAcceptanceCommands"),
        )

    def test_rejects_legacy_string_command(self) -> None:
        packet = 'offlineAcceptanceCommands: ["python3 -c print(1)"]\n'
        with self.assertRaises(RUNNER.PacketTransportError):
            RUNNER.load_command_field(packet, "offlineAcceptanceCommands")

    def test_rejects_shell_recursive_verify_fetch_and_bare_uv(self) -> None:
        refused = [
            ["sh", "-c", "true"],
            ["/usr/bin/zsh", "-c", "true"],
            ["make", "verify-offline"],
            ["make", "prefetch"],
            ["uv", "run", "pytest"],
        ]
        for command in refused:
            with self.subTest(command=command), self.assertRaises(
                RUNNER.PacketTransportError
            ):
                RUNNER.validate_offline_argv(command)

    def test_accepts_frozen_offline_uv_argv(self) -> None:
        RUNNER.validate_offline_argv(
            ["uv", "run", "--offline", "--frozen", "--no-sync", "pytest"]
        )

    def test_reads_packet_through_read_only_descriptor(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "packet.yaml"
            path.write_text(
                "offlineExecution: " + json.dumps(RUNNER.EXPECTED_EXECUTION) + "\n",
                encoding="utf-8",
            )
            text, digest = RUNNER.read_packet_text(path)
        self.assertIn("offlineExecution", text)
        self.assertEqual(64, len(digest))

    def test_wrapper_runs_direct_argv_inside_os_isolation(self) -> None:
        if os.environ.get("HARNESS_OFFLINE_ENFORCED") == "1":
            self.skipTest(
                "trusted outer gate owns isolation; nested sandboxing is prohibited"
            )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "packet.yaml"
            command = [
                sys.executable,
                "-c",
                "import os; assert os.environ['UV_OFFLINE'] == '1'; assert os.environ['HARNESS_OFFLINE_ENFORCED'] == '1'; assert 'HARNESS_TASK_PACKET' not in os.environ",
            ]
            path.write_text(
                "prefetchCommands: []\n"
                + "offlineAcceptanceCommands: "
                + json.dumps([command], separators=(",", ":"))
                + "\n"
                + "offlineExecution: "
                + json.dumps(RUNNER.EXPECTED_EXECUTION, separators=(",", ":"))
                + "\n",
                encoding="utf-8",
            )
            environment = os.environ.copy()
            environment["HARNESS_TASK_PACKET"] = str(path)
            set_warm_root_contract(environment)
            completed = subprocess.run(
                [str(Path(__file__).with_name("verify-offline.sh"))],
                env=environment,
                text=True,
                capture_output=True,
                check=False,
            )
        if completed.returncode == 2 and "offline verification refused" in completed.stderr:
            self.skipTest(completed.stderr.strip())
        self.assertEqual(0, completed.returncode, completed.stdout + completed.stderr)

    def test_wrapper_denies_packet_mutation_at_os_boundary(self) -> None:
        if os.environ.get("HARNESS_OFFLINE_ENFORCED") == "1":
            self.skipTest(
                "trusted outer gate owns isolation; nested sandboxing is prohibited"
            )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "packet.yaml"
            command = [
                sys.executable,
                "-c",
                "from pathlib import Path; import sys; Path(sys.argv[1]).write_text('mutated\\n')",
                str(path),
            ]
            original = (
                "prefetchCommands: []\n"
                + "offlineAcceptanceCommands: "
                + json.dumps([command], separators=(",", ":"))
                + "\n"
                + "offlineExecution: "
                + json.dumps(RUNNER.EXPECTED_EXECUTION, separators=(",", ":"))
                + "\n"
            )
            path.write_text(original, encoding="utf-8")
            environment = os.environ.copy()
            environment["HARNESS_TASK_PACKET"] = str(path)
            set_warm_root_contract(environment)
            completed = subprocess.run(
                [str(Path(__file__).with_name("verify-offline.sh"))],
                env=environment,
                text=True,
                capture_output=True,
                check=False,
            )
            retained = path.read_text(encoding="utf-8")
        if completed.returncode == 2 and "offline verification refused" in completed.stderr:
            self.skipTest(completed.stderr.strip())
        self.assertNotEqual(0, completed.returncode, completed.stdout + completed.stderr)
        self.assertEqual(original, retained)

    def test_wrapper_hides_and_denies_declared_warm_source_root(self) -> None:
        if os.environ.get("HARNESS_OFFLINE_ENFORCED") == "1":
            self.skipTest(
                "trusted outer gate owns isolation; nested sandboxing is prohibited"
            )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            warm_root = root / "warm-source"
            warm_root.mkdir()
            secret = warm_root / "reference.txt"
            secret.write_text("must remain unavailable\n", encoding="utf-8")
            packet = root / "packet.yaml"
            command = [
                sys.executable,
                "-c",
                """\
import os
import sys
from pathlib import Path

root = Path(sys.argv[1])
secret = root / "reference.txt"
assert "HARNESS_WARM_SOURCE_ROOTS" not in os.environ
try:
    root.stat()
except OSError:
    pass
else:
    raise SystemExit("warm source metadata remained discoverable")
try:
    secret.read_bytes()
except OSError:
    pass
else:
    raise SystemExit("warm source remained readable")
try:
    (root / "mutation.txt").write_text("forbidden", encoding="utf-8")
except OSError:
    pass
else:
    raise SystemExit("warm source remained writable")
""",
                str(warm_root),
            ]
            packet.write_text(
                "prefetchCommands: []\n"
                + "offlineAcceptanceCommands: "
                + json.dumps([command], separators=(",", ":"))
                + "\n"
                + "offlineExecution: "
                + json.dumps(RUNNER.EXPECTED_EXECUTION, separators=(",", ":"))
                + "\n",
                encoding="utf-8",
            )
            environment = os.environ.copy()
            environment["HARNESS_TASK_PACKET"] = str(packet)
            set_warm_root_contract(environment, warm_root)
            completed = subprocess.run(
                [str(Path(__file__).with_name("verify-offline.sh"))],
                env=environment,
                text=True,
                capture_output=True,
                check=False,
            )
        if completed.returncode == 2 and "offline verification refused" in completed.stderr:
            self.skipTest(completed.stderr.strip())
        self.assertEqual(0, completed.returncode, completed.stdout + completed.stderr)

    def test_wrapper_requires_detected_locked_warm_root_declaration(self) -> None:
        if os.environ.get("HARNESS_OFFLINE_ENFORCED") == "1":
            self.skipTest(
                "trusted outer gate owns isolation; nested wrapper validation is prohibited"
            )
        with tempfile.TemporaryDirectory(
            prefix="codex-harness-warmstarts.", dir="/tmp"
        ) as directory, tempfile.TemporaryDirectory() as packet_directory:
            locked = Path(directory) / "source"
            (locked / ".git").mkdir(parents=True)
            (locked / ".git/config").write_text(
                "[remote \"origin\"]\n"
                "url = no-fetch://immutable-warm-source\n"
                "pushurl = no-push://immutable-warm-source\n",
                encoding="utf-8",
            )
            packet = Path(packet_directory) / "packet.yaml"
            packet.write_text("fixture: detection-only\n", encoding="utf-8")
            environment = os.environ.copy()
            environment["HARNESS_TASK_PACKET"] = str(packet)
            environment["HARNESS_WARM_SOURCE_ROOTS"] = "NONE"
            completed = subprocess.run(
                [str(Path(__file__).with_name("verify-offline.sh"))],
                env=environment,
                text=True,
                capture_output=True,
                check=False,
            )
        self.assertEqual(2, completed.returncode, completed.stdout + completed.stderr)
        self.assertIn("absent from HARNESS_WARM_SOURCE_ROOTS", completed.stderr)

    def test_wrapper_requires_explicit_trusted_warm_root_contract(self) -> None:
        if os.environ.get("HARNESS_OFFLINE_ENFORCED") == "1":
            self.skipTest(
                "trusted outer gate owns isolation; nested wrapper validation is prohibited"
            )
        with tempfile.TemporaryDirectory() as directory:
            packet = Path(directory) / "packet.yaml"
            packet.write_text("fixture: declaration-only\n", encoding="utf-8")
            for declaration in (None, ""):
                environment = os.environ.copy()
                environment["HARNESS_TASK_PACKET"] = str(packet)
                if declaration is None:
                    environment.pop("HARNESS_WARM_SOURCE_ROOTS", None)
                else:
                    environment["HARNESS_WARM_SOURCE_ROOTS"] = declaration
                completed = subprocess.run(
                    [str(Path(__file__).with_name("verify-offline.sh"))],
                    env=environment,
                    text=True,
                    capture_output=True,
                    check=False,
                )
                with self.subTest(declaration=declaration):
                    self.assertEqual(
                        2,
                        completed.returncode,
                        completed.stdout + completed.stderr,
                    )
                    self.assertIn("HARNESS_WARM_SOURCE_ROOTS must be", completed.stderr)

    def test_launchers_define_macos_and_linux_warm_source_boundaries(self) -> None:
        packet_launcher = Path(__file__).with_name("verify-offline.sh").read_text(
            encoding="utf-8"
        )
        repository_launcher = (
            Path(__file__).resolve().parents[1] / "scripts/verify_offline.sh"
        ).read_text(encoding="utf-8")
        for launcher in (packet_launcher, repository_launcher):
            self.assertIn("(deny file-read*", launcher)
            self.assertIn("(deny file-write*", launcher)
            self.assertIn("--blacklist=${warm_root}", launcher)
            self.assertIn("--read-only=${warm_root}", launcher)
        self.assertNotIn("unshare --user", repository_launcher)

    def test_wrapper_starts_the_runner_in_isolated_mode(self) -> None:
        # The runner prints the evidence lines, so modules planted in its own
        # directory, PYTHON* variables or user site-packages must not shadow the
        # standard library it imports.
        launcher = Path(__file__).with_name("verify-offline.sh").read_text(
            encoding="utf-8"
        )
        # Every reference to the runner, however spelled, is one of the three isolated calls.
        self.assertEqual(
            ['exec python3 -I "$runner"', 'python3 -I "$runner"', 'python3 -I "$runner"'],
            [
                line.strip()
                for line in launcher.splitlines()
                if re.search(r"\$\{?runner\b", line)
            ],
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "argparse.py").write_text(
                "raise SystemExit('planted module imported')\n", encoding="utf-8"
            )
            script = root / "runner.py"
            script.write_text("import argparse\nprint('standard library')\n", encoding="utf-8")
            environment = os.environ.copy()
            environment.pop("PYTHONSAFEPATH", None)
            environment["PYTHONPATH"] = str(root)
            plain, isolated = (
                subprocess.run(
                    [sys.executable, *flags, str(script)],
                    env=environment,
                    text=True,
                    capture_output=True,
                    check=False,
                )
                for flags in ((), ("-I",))
            )
        self.assertIn("planted module imported", plain.stderr)
        self.assertEqual(
            (0, "standard library\n"),
            (isolated.returncode, isolated.stdout),
            isolated.stderr,
        )

    def test_runner_starts_the_network_canary_in_isolated_mode(self) -> None:
        # Every interpreter the runner starts from its own directory is isolated too.
        source = Path(__file__).with_name("run_packet_argv.py").read_text(encoding="utf-8")
        launches = [
            node
            for node in ast.walk(ast.parse(source))
            if isinstance(node, (ast.List, ast.Tuple))
            and node.elts
            and ast.unparse(node.elts[0]) == "sys.executable"
        ]
        self.assertEqual(1, len(launches))
        self.assertEqual("'-I'", ast.unparse(launches[0].elts[1]))
        self.assertEqual(1, source.count("sys.executable"))

    def test_detects_packet_mutation_after_child_command(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "packet.yaml"
            path.write_text("authority: original\n", encoding="utf-8")
            _, digest = RUNNER.read_packet_text(path)
            command = [
                sys.executable,
                "-c",
                "from pathlib import Path; import sys; Path(sys.argv[1]).write_text('authority: changed\\n')",
                str(path),
            ]
            with self.assertRaises(RUNNER.PacketTransportError):
                RUNNER.run_commands(
                    [command],
                    environment=os.environ.copy(),
                    packet_path=path,
                    packet_digest=digest,
                    phase="mutation-fixture",
                )

    def test_scrubs_packet_and_provider_credentials_from_children(self) -> None:
        environment = {
            "PATH": os.environ.get("PATH", ""),
            "HARNESS_TASK_PACKET": "/tmp/packet.yaml",
            "OPENAI_API_KEY": "forbidden",
            "AWS_ACCESS_KEY_ID": "forbidden",
            "AWS_SESSION_TOKEN": "forbidden",
            "KUBECONFIG": "/tmp/forbidden-kubeconfig",
            "DOCKER_CONFIG": "/tmp/forbidden-docker-config",
            "WARM_SOURCE_ROOT": "/tmp/forbidden-source",
            "SAFE_LOCAL_SETTING": "must-not-pass",
            "HARNESS_OFFLINE_ENFORCED": "1",
        }
        scrubbed = RUNNER.scrub_environment(environment)
        self.assertEqual("1", scrubbed["HARNESS_OFFLINE_ENFORCED"])
        self.assertNotIn("HARNESS_TASK_PACKET", scrubbed)
        self.assertNotIn("OPENAI_API_KEY", scrubbed)
        self.assertNotIn("AWS_ACCESS_KEY_ID", scrubbed)
        self.assertNotIn("AWS_SESSION_TOKEN", scrubbed)
        self.assertNotIn("KUBECONFIG", scrubbed)
        self.assertNotIn("DOCKER_CONFIG", scrubbed)
        self.assertNotIn("WARM_SOURCE_ROOT", scrubbed)
        self.assertNotIn("SAFE_LOCAL_SETTING", scrubbed)


if __name__ == "__main__":
    unittest.main()

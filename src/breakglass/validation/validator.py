"""Sandbox validator abstraction interface and sandbox implementations."""

from abc import ABC, abstractmethod
import os
import sys
import json
import subprocess
import time
import math
import threading
import queue
import uuid
from typing import Dict, Any, Optional, Tuple
from breakglass.inspection.models import RepositoryReport
from breakglass.reasoning.models import SecurityHypothesis, EvidenceReference
from breakglass.validation.models import ValidationResult, ValidationStatus


class SandboxValidator(ABC):
    """Abstract interface representing a sandbox validation environment."""

    @abstractmethod
    def validate(
        self,
        hypothesis: SecurityHypothesis,
        repository_context: RepositoryReport,
        cancellation_event: Optional[threading.Event] = None
    ) -> ValidationResult:
        """Validates a SecurityHypothesis inside a sandboxed environment.

        Args:
            hypothesis: The hypothesis to validate.
            repository_context: The authoritative codebase report.
            cancellation_event: Optional event to trigger cooperative cancellation.

        Returns:
            A ValidationResult representing the outcome.
        """
        pass


class MockSandboxValidator(SandboxValidator):
    """Mock validator returning predefined validation results for testing."""

    def __init__(self, predefined_results: Optional[Dict[str, ValidationResult]] = None):
        self.predefined_results = predefined_results or {}
        self.last_validated = []

    def validate(
        self,
        hypothesis: SecurityHypothesis,
        repository_context: RepositoryReport,
        cancellation_event: Optional[threading.Event] = None
    ) -> ValidationResult:
        """Saves calls and returns configured or fallback validation results."""
        self.last_validated.append((hypothesis, repository_context))
        if hypothesis.id in self.predefined_results:
            return self.predefined_results[hypothesis.id]

        # Default fallback
        return ValidationResult(
            hypothesis_id=hypothesis.id,
            status=ValidationStatus.NOT_CONFIRMED,
            attempted=True,
            confirmed=False,
            evidence="Mock validation fallback: not confirmed"
        )


class _CombinedOutputCounter:
    """Thread-safe counter to track combined stdout and stderr bytes."""
    def __init__(self, limit: int):
        self._lock = threading.Lock()
        self._value = 0
        self._limit = limit

    def add(self, amount: int) -> bool:
        with self._lock:
            self._value += amount
            return self._value >= self._limit

    @property
    def value(self) -> int:
        with self._lock:
            return self._value


def _is_contained_in(parent: str, child: str) -> bool:
    """Verifies component-aware containment of child path inside parent path.

    Prevents substring/prefix overmatching and symlink/junction escapes.
    """
    try:
        p_canon = os.path.normcase(os.path.abspath(os.path.realpath(parent)))
        c_canon = os.path.normcase(os.path.abspath(os.path.realpath(child)))

        # Verify drive letters match on Windows to avoid ValueError in commonpath
        p_drive, _ = os.path.splitdrive(p_canon)
        c_drive, _ = os.path.splitdrive(c_canon)
        if p_drive != c_drive:
            return False

        common = os.path.commonpath([p_canon, c_canon])
        return os.path.normcase(common) == p_canon
    except Exception:
        return False


def _validate_mount_path(path: str) -> str:
    """Validates and canonicalizes a path for mounting or sandboxed validation.

    Rejects paths that escape, UNC paths, and forbidden host roots/system dirs.
    """
    if not path:
        raise ValueError("Mount path is empty")

    # Canonicalize path (resolve symlinks, relative path segments, and drives)
    resolved = os.path.abspath(os.path.realpath(path))

    # Check existence
    if not os.path.exists(resolved):
        raise ValueError(f"Mount path does not exist: {resolved}")

    # Check if UNC path on Windows
    if os.name == 'nt' and resolved.startswith('\\\\'):
        raise ValueError(f"UNC paths are not allowed for sandbox mounts: {resolved}")

    # Check against forbidden paths
    forbidden_directories = []

    if os.name == 'nt':
        # Retrieve actual environment variables for Windows system/env directories
        sys_root = os.environ.get("SystemRoot") or os.environ.get("windir")
        prog_files = os.environ.get("ProgramFiles")
        prog_files_x86 = os.environ.get("ProgramFiles(x86)")
        user_prof = os.environ.get("USERPROFILE") or os.environ.get("UserProfile")
        all_user_prof = os.environ.get("ProgramData") or os.environ.get("ALLUSERSPROFILE")

        # Gather all valid paths
        for raw_path in [sys_root, prog_files, prog_files_x86, user_prof, all_user_prof]:
            if raw_path:
                try:
                    forbidden_directories.append(os.path.abspath(os.path.realpath(raw_path)))
                except Exception:
                    pass

        # Avoid mounting drive root
        drive, tail = os.path.splitdrive(resolved)
        if not tail or tail.strip(os.sep) == "":
            raise ValueError(f"Mounting drive root is forbidden: {resolved}")
    else:
        # Standard Unix system root and paths
        if resolved == "/":
            raise ValueError("Mounting root directory is forbidden")

        forbidden_directories = [
            "/etc", "/var", "/usr", "/bin", "/sbin", "/lib", "/sys", "/proc", "/dev", "/boot"
        ]

    # Enforce component-aware commonpath validation
    for forbidden_dir in forbidden_directories:
        if _is_contained_in(forbidden_dir, resolved):
            raise ValueError(f"Mounting system path is forbidden: {resolved}")

    # Platform-aware component parts check (using pathlib.Path for clean segments)
    from pathlib import Path
    parts = Path(resolved).parts
    parts_lower = [p.lower() for p in parts]

    # 1. Alternate Windows system path roots (Windows only)
    if os.name == 'nt':
        # If parts has at least 2 components, verify the first directory level
        if len(parts_lower) > 1:
            forbidden_roots = {"windows", "program files", "program files (x86)", "programdata"}
            if parts_lower[1] in forbidden_roots:
                raise ValueError(f"System path is forbidden: {resolved}")

    # 2. Block sensitive credential/control folders (e.g. .ssh, .aws, .docker)
    sensitive_folders = {".ssh", ".aws", ".docker"}
    for part in parts_lower:
        if part in sensitive_folders:
            raise ValueError(f"Mounting sensitive credential/control path is forbidden: {resolved}")

    # 3. Block Docker socket files (e.g. docker.sock)
    if "docker.sock" in parts_lower:
        raise ValueError(f"Mounting sensitive credential/control path is forbidden: {resolved}")

    # 4. Block private keys (e.g. id_rsa, id_dsa, id_ecdsa, id_ed25519)
    if parts_lower:
        filename = parts_lower[-1]
        sensitive_files = {"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"}
        if filename in sensitive_files:
            raise ValueError(f"Mounting sensitive credential/control path is forbidden: {resolved}")

    return resolved


class SandboxBackend(ABC):
    """Abstraction for validation execution backends (local subprocess vs container)."""

    @abstractmethod
    def execute(
        self,
        runner_path: str,
        repo_path: str,
        payload_json: str,
        timeout: float,
        max_output_bytes: int,
        cancellation_event: Optional[threading.Event] = None
    ) -> Tuple[str, str, int, bool, bool, Optional[str]]:
        """Executes the validation runner.

        Returns:
            Tuple containing:
            (stdout_data, stderr_data, returncode, timeout_hit, overflow_hit, error_message)
        """
        pass


class SubprocessSandboxBackend(SandboxBackend):
    """Local development/simulation subprocess validation backend."""

    def __init__(self, reader_thread_fn):
        self._reader_thread_fn = reader_thread_fn

    def _writer_thread(self, stream: Any, data: str) -> None:
        """Writes data to stdin stream pipe and closes it."""
        try:
            stream.write(data)
            stream.close()
        except Exception:
            pass

    def execute(
        self,
        runner_path: str,
        repo_path: str,
        payload_json: str,
        timeout: float,
        max_output_bytes: int,
        cancellation_event: Optional[threading.Event] = None
    ) -> Tuple[str, str, int, bool, bool, Optional[str]]:
        cmd = [sys.executable, "-u", runner_path]
        env = dict(os.environ)
        pythonpath = env.get("PYTHONPATH", "")
        src_path = os.path.abspath("src")
        if src_path not in pythonpath:
            env["PYTHONPATH"] = f"{src_path}{os.pathsep}{pythonpath}".strip(os.pathsep)

        start_time = time.perf_counter()
        try:
            proc = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=env
            )
        except Exception as e:
            return "", "", -1, False, False, f"Failed to spawn subprocess: {str(e)}"

        max_q_size = max(5, max_output_bytes // 1024 + 2)
        q_out = queue.Queue(maxsize=max_q_size)
        q_err = queue.Queue(maxsize=max_q_size)

        counter = _CombinedOutputCounter(max_output_bytes)
        overflow_event = threading.Event()
        shutdown_event = threading.Event()

        t_out = threading.Thread(
            target=self._reader_thread_fn,
            args=(proc.stdout, q_out, counter, proc, overflow_event, shutdown_event),
            daemon=True
        )
        t_err = threading.Thread(
            target=self._reader_thread_fn,
            args=(proc.stderr, q_err, counter, proc, overflow_event, shutdown_event),
            daemon=True
        )
        t_out.start()
        t_err.start()

        t_in = threading.Thread(target=self._writer_thread, args=(proc.stdin, payload_json), daemon=True)
        t_in.start()

        stdout_chunks = []
        stderr_chunks = []
        timeout_hit = False
        overflow_hit = False

        while True:
            # Check cancellation first
            if cancellation_event and cancellation_event.is_set():
                timeout_hit = True
                break

            while not q_out.empty():
                try:
                    stdout_chunks.append(q_out.get_nowait())
                except queue.Empty:
                    break

            while not q_err.empty():
                try:
                    stderr_chunks.append(q_err.get_nowait())
                except queue.Empty:
                    break

            if overflow_event.is_set():
                overflow_hit = True
                break

            if time.perf_counter() - start_time > timeout:
                timeout_hit = True
                break

            ret = proc.poll()
            if ret is not None:
                break

            time.sleep(0.01)

        if overflow_hit or timeout_hit:
            shutdown_event.set()
            if not overflow_hit:
                try:
                    proc.kill()
                except Exception:
                    pass
            proc.wait()
            t_out.join(timeout=1.0)
            t_err.join(timeout=1.0)
            try:
                proc.stdout.close()
                proc.stderr.close()
            except Exception:
                pass
            return "".join(stdout_chunks), "".join(stderr_chunks), proc.returncode, timeout_hit, overflow_hit, None

        proc.wait()
        t_out.join(timeout=1.0)
        t_err.join(timeout=1.0)
        shutdown_event.set()

        while not q_out.empty():
            try:
                stdout_chunks.append(q_out.get_nowait())
            except queue.Empty:
                break
        while not q_err.empty():
            try:
                stderr_chunks.append(q_err.get_nowait())
            except queue.Empty:
                break

        try:
            proc.stdout.close()
            proc.stderr.close()
        except Exception:
            pass

        return "".join(stdout_chunks), "".join(stderr_chunks), proc.returncode, False, False, None


class DockerSandboxBackend(SandboxBackend):
    """Isolated container validation execution backend using Docker."""

    def __init__(self, reader_thread_fn, image_name: str = "python:3.11-slim"):
        self._reader_thread_fn = reader_thread_fn
        self.image_name = image_name

    def _writer_thread(self, stream: Any, data: str) -> None:
        """Writes data to stdin stream pipe and closes it."""
        try:
            stream.write(data)
            stream.close()
        except Exception:
            pass

    def _kill_container(self, container_name: str, proc: subprocess.Popen) -> None:
        """Forcefully kills and removes the container and its wrapper process."""
        try:
            proc.kill()
        except Exception:
            pass
        try:
            subprocess.run(["docker", "kill", container_name], capture_output=True, timeout=5)
        except Exception:
            pass
        try:
            subprocess.run(["docker", "rm", "-f", container_name], capture_output=True, timeout=5)
        except Exception:
            pass

    def execute(
        self,
        runner_path: str,
        repo_path: str,
        payload_json: str,
        timeout: float,
        max_output_bytes: int,
        cancellation_event: Optional[threading.Event] = None
    ) -> Tuple[str, str, int, bool, bool, Optional[str]]:
        # 1. Path containment validations on the host side before mounting
        try:
            valid_repo_path = _validate_mount_path(repo_path)
            valid_runner_path = _validate_mount_path(runner_path)
        except Exception as e:
            return "", "", -1, False, False, f"Preflight path validation failed: {str(e)}"

        container_name = f"breakglass-sandbox-{uuid.uuid4().hex}"

        # 2. Construct container execution command line with privilege & network isolation
        cmd = [
            "docker", "run",
            "--name", container_name,
            "--rm",
            "-i",
            "--network", "none",
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            "--user", "1000:1000",
            "--memory", "256m",
            "--cpus", "1.0",
            "--pids-limit", "64",
            "-v", f"{valid_repo_path}:/workspace:ro",
            "-v", f"{valid_runner_path}:/app/sandbox_runner.py:ro",
            "-w", "/workspace",
            self.image_name,
            "python", "-u", "/app/sandbox_runner.py"
        ]

        start_time = time.perf_counter()
        try:
            proc = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
        except Exception as e:
            return "", "", -1, False, False, f"Failed to spawn docker process: {str(e)}"

        max_q_size = max(5, max_output_bytes // 1024 + 2)
        q_out = queue.Queue(maxsize=max_q_size)
        q_err = queue.Queue(maxsize=max_q_size)

        counter = _CombinedOutputCounter(max_output_bytes)
        overflow_event = threading.Event()
        shutdown_event = threading.Event()

        # Wrap kill_container to use Docker-specific teardown
        def docker_kill_fn():
            self._kill_container(container_name, proc)

        # Modify reader thread target slightly or patch proc.kill to handle docker cleanup
        class ProcProxy:
            def __init__(self, original_proc, kill_fn):
                self._proc = original_proc
                self._kill_fn = kill_fn
            def kill(self):
                self._kill_fn()
            def __getattr__(self, name):
                return getattr(self._proc, name)

        proc_proxy = ProcProxy(proc, docker_kill_fn)

        t_out = threading.Thread(
            target=self._reader_thread_fn,
            args=(proc.stdout, q_out, counter, proc_proxy, overflow_event, shutdown_event),
            daemon=True
        )
        t_err = threading.Thread(
            target=self._reader_thread_fn,
            args=(proc.stderr, q_err, counter, proc_proxy, overflow_event, shutdown_event),
            daemon=True
        )
        t_out.start()
        t_err.start()

        t_in = threading.Thread(target=self._writer_thread, args=(proc.stdin, payload_json), daemon=True)
        t_in.start()

        stdout_chunks = []
        stderr_chunks = []
        timeout_hit = False
        overflow_hit = False

        while True:
            # Check cancellation first
            if cancellation_event and cancellation_event.is_set():
                timeout_hit = True
                break

            while not q_out.empty():
                try:
                    stdout_chunks.append(q_out.get_nowait())
                except queue.Empty:
                    break

            while not q_err.empty():
                try:
                    stderr_chunks.append(q_err.get_nowait())
                except queue.Empty:
                    break

            if overflow_event.is_set():
                overflow_hit = True
                break

            if time.perf_counter() - start_time > timeout:
                timeout_hit = True
                break

            ret = proc.poll()
            if ret is not None:
                break

            time.sleep(0.01)

        if overflow_hit or timeout_hit:
            shutdown_event.set()
            docker_kill_fn()
            proc.wait()
            t_out.join(timeout=1.0)
            t_err.join(timeout=1.0)
            try:
                proc.stdout.close()
                proc.stderr.close()
            except Exception:
                pass
            return "".join(stdout_chunks), "".join(stderr_chunks), proc.returncode, timeout_hit, overflow_hit, None

        proc.wait()
        t_out.join(timeout=1.0)
        t_err.join(timeout=1.0)
        shutdown_event.set()

        while not q_out.empty():
            try:
                stdout_chunks.append(q_out.get_nowait())
            except queue.Empty:
                break
        while not q_err.empty():
            try:
                stderr_chunks.append(q_err.get_nowait())
            except queue.Empty:
                break

        try:
            proc.stdout.close()
            proc.stderr.close()
        except Exception:
            pass

        return "".join(stdout_chunks), "".join(stderr_chunks), proc.returncode, False, False, None


class TrueForgeSandboxValidator(SandboxValidator):
    """Adapter boundary for the TrueForge execution sandbox."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        endpoint: Optional[str] = None,
        local_sandbox: Optional[bool] = None,
        container_sandbox: Optional[bool] = None,
        image_name: Optional[str] = None,
        timeout_seconds: Optional[float] = None,
        max_output_bytes: Optional[int] = None
    ):
        # Read from environment variables if not provided
        self.api_key = api_key or os.environ.get("TRUEFORGE_API_KEY")
        self.endpoint = endpoint or os.environ.get("TRUEFORGE_ENDPOINT", "https://api.trueforge.example.com")

        if local_sandbox is not None:
            self.local_sandbox = local_sandbox
        else:
            self.local_sandbox = os.environ.get("TRUEFORGE_LOCAL_SANDBOX") == "true"

        if container_sandbox is not None:
            self.container_sandbox = container_sandbox
        else:
            self.container_sandbox = os.environ.get("TRUEFORGE_CONTAINER_SANDBOX") == "true"

        self.image_name = image_name or os.environ.get("TRUEFORGE_SANDBOX_IMAGE", "python:3.11-slim")

        # Read limits
        self.timeout_seconds = timeout_seconds or float(os.environ.get("TRUEFORGE_TIMEOUT", "30.0"))
        self.max_output_bytes = max_output_bytes or int(os.environ.get("TRUEFORGE_MAX_OUTPUT", "1048576")) # 1MB

    def _to_canonical_dict(self, obj: Any) -> Any:
        """Recursively converts objects to canonical JSON serializable representation."""
        if hasattr(obj, "to_dict") and callable(obj.to_dict):
            return obj.to_dict()
        elif hasattr(obj, "__dict__"):
            return {k: self._to_canonical_dict(v) for k, v in obj.__dict__.items() if not k.startswith("_")}
        elif isinstance(obj, list):
            return [self._to_canonical_dict(x) for x in obj]
        elif isinstance(obj, dict):
            return {k: self._to_canonical_dict(v) for k, v in obj.items()}
        elif isinstance(obj, (str, int, float, bool)) or obj is None:
            return obj
        else:
            return str(obj)

    def _reader_thread(
        self,
        stream: Any,
        q: queue.Queue,
        counter: _CombinedOutputCounter,
        proc: Any,
        overflow_event: threading.Event,
        shutdown_event: threading.Event
    ) -> None:
        """Reads chunks of output from a stream pipe and pushes them to a queue."""
        try:
            while not shutdown_event.is_set():
                chunk = stream.read(1024)
                if not chunk or "Mock" in type(chunk).__name__:
                    break

                # Safe byte count computation
                chunk_len = len(chunk.encode("utf-8") if isinstance(chunk, str) else chunk)

                # Check and add to counter
                if counter.add(chunk_len):
                    overflow_event.set()
                    try:
                        proc.kill()
                    except Exception:
                        pass
                    break

                # Enqueue with timeout to prevent deadlocks
                enqueued = False
                while not shutdown_event.is_set():
                    try:
                        q.put(chunk, timeout=0.05)
                        enqueued = True
                        break
                    except queue.Full:
                        continue

                if not enqueued:
                    break
        except Exception:
            pass

    def _writer_thread(self, stream: Any, data: str) -> None:
        """Writes data to stdin stream pipe and closes it."""
        try:
            stream.write(data)
            stream.close()
        except Exception:
            pass

    def _execute_sandbox(
        self,
        backend: SandboxBackend,
        hypothesis: SecurityHypothesis,
        payload_json: str,
        runner_path: str,
        repo_path: str,
        cancellation_event: Optional[threading.Event] = None
    ) -> ValidationResult:
        start_time = time.perf_counter()

        stdout_data, stderr_data, returncode, timeout_hit, overflow_hit, error_message = backend.execute(
            runner_path=runner_path,
            repo_path=repo_path,
            payload_json=payload_json,
            timeout=self.timeout_seconds,
            max_output_bytes=self.max_output_bytes,
            cancellation_event=cancellation_event
        )

        duration = time.perf_counter() - start_time

        if error_message:
            return ValidationResult(
                hypothesis_id=hypothesis.id,
                status=ValidationStatus.SANDBOX_ERROR,
                attempted=True,
                confirmed=False,
                error_message=error_message
            )

        if overflow_hit:
            return ValidationResult(
                hypothesis_id=hypothesis.id,
                status=ValidationStatus.SANDBOX_ERROR,
                attempted=True,
                confirmed=False,
                error_message=f"Sandbox execution aborted: combined output size exceeded limit of {self.max_output_bytes} bytes"
            )

        if timeout_hit:
            return ValidationResult(
                hypothesis_id=hypothesis.id,
                status=ValidationStatus.TIMEOUT,
                attempted=True,
                confirmed=False,
                error_message=f"Sandbox execution timed out after {self.timeout_seconds} seconds"
            )

        if returncode != 0:
            return ValidationResult(
                hypothesis_id=hypothesis.id,
                status=ValidationStatus.SANDBOX_ERROR,
                attempted=True,
                confirmed=False,
                error_message=f"Sandbox process exited with code {returncode}. Stderr: {stderr_data.strip()}"
            )

        # 4. JSON Payload Schema Validation
        try:
            result_data = json.loads(stdout_data)
        except Exception as e:
            return ValidationResult(
                hypothesis_id=hypothesis.id,
                status=ValidationStatus.SANDBOX_ERROR,
                attempted=True,
                confirmed=False,
                error_message=f"Sandbox output was not valid JSON: {str(e)}"
            )

        if not isinstance(result_data, dict):
            return ValidationResult(
                hypothesis_id=hypothesis.id,
                status=ValidationStatus.SANDBOX_ERROR,
                attempted=True,
                confirmed=False,
                error_message="Sandbox output JSON is not a dictionary"
            )

        # Validate status enum
        status_val = result_data.get("status")
        if not isinstance(status_val, str):
            return ValidationResult(
                hypothesis_id=hypothesis.id,
                status=ValidationStatus.SANDBOX_ERROR,
                attempted=True,
                confirmed=False,
                error_message="Sandbox status field must be a string"
            )
        try:
            status = ValidationStatus(status_val)
        except ValueError:
            return ValidationResult(
                hypothesis_id=hypothesis.id,
                status=ValidationStatus.SANDBOX_ERROR,
                attempted=True,
                confirmed=False,
                error_message=f"Sandbox status field contains invalid status: {status_val}"
            )

        # Validate attempted/confirmed
        attempted_val = result_data.get("attempted")
        confirmed_val = result_data.get("confirmed")
        if type(attempted_val) is not bool or type(confirmed_val) is not bool:
            return ValidationResult(
                hypothesis_id=hypothesis.id,
                status=ValidationStatus.SANDBOX_ERROR,
                attempted=True,
                confirmed=False,
                error_message="Sandbox attempted and confirmed fields must be exactly booleans"
            )

        # Validate confidence_delta
        conf_delta_val = result_data.get("confidence_delta")
        if not isinstance(conf_delta_val, (int, float)) or isinstance(conf_delta_val, bool):
            return ValidationResult(
                hypothesis_id=hypothesis.id,
                status=ValidationStatus.SANDBOX_ERROR,
                attempted=True,
                confirmed=False,
                error_message="Sandbox confidence_delta field must be a float or int (and not bool)"
            )
        if not math.isfinite(conf_delta_val) or not (-1.0 <= conf_delta_val <= 1.0):
            return ValidationResult(
                hypothesis_id=hypothesis.id,
                status=ValidationStatus.SANDBOX_ERROR,
                attempted=True,
                confirmed=False,
                error_message=f"Sandbox confidence_delta field must be a finite number between -1.0 and 1.0: {conf_delta_val}"
            )

        # Validate other required fields: evidence, stdout, stderr
        evidence_val = result_data.get("evidence")
        stdout_val = result_data.get("stdout")
        stderr_val = result_data.get("stderr")
        if not isinstance(evidence_val, str) or not isinstance(stdout_val, str) or not isinstance(stderr_val, str):
            return ValidationResult(
                hypothesis_id=hypothesis.id,
                status=ValidationStatus.SANDBOX_ERROR,
                attempted=True,
                confirmed=False,
                error_message="Sandbox evidence, stdout, and stderr must be strings"
            )

        metadata_val = result_data.get("metadata")
        if metadata_val is not None:
            if not isinstance(metadata_val, dict):
                return ValidationResult(
                    hypothesis_id=hypothesis.id,
                    status=ValidationStatus.SANDBOX_ERROR,
                    attempted=True,
                    confirmed=False,
                    error_message="Sandbox metadata must be a dictionary"
                )
            try:
                json.dumps(metadata_val)
            except Exception:
                return ValidationResult(
                    hypothesis_id=hypothesis.id,
                    status=ValidationStatus.SANDBOX_ERROR,
                    attempted=True,
                    confirmed=False,
                    error_message="Sandbox metadata is not JSON serializable"
                )
        else:
            metadata_val = {}

        err_msg_val = result_data.get("error_message")
        if err_msg_val is not None and not isinstance(err_msg_val, str):
            return ValidationResult(
                hypothesis_id=hypothesis.id,
                status=ValidationStatus.SANDBOX_ERROR,
                attempted=True,
                confirmed=False,
                error_message="Sandbox error_message must be a string or None"
            )

        duration_val = result_data.get("duration")
        if duration_val is not None:
            if not isinstance(duration_val, (int, float)) or isinstance(duration_val, bool):
                return ValidationResult(
                    hypothesis_id=hypothesis.id,
                    status=ValidationStatus.SANDBOX_ERROR,
                    attempted=True,
                    confirmed=False,
                    error_message="Sandbox duration must be a float or int (and not bool)"
                )
            if not math.isfinite(duration_val) or duration_val < 0:
                return ValidationResult(
                    hypothesis_id=hypothesis.id,
                    status=ValidationStatus.SANDBOX_ERROR,
                    attempted=True,
                    confirmed=False,
                    error_message=f"Sandbox duration must be a non-negative finite number: {duration_val}"
                )
        else:
            duration_val = duration

        # Validate state invariants strictly
        invariants = {
            ValidationStatus.NOT_ATTEMPTED: (False, False),
            ValidationStatus.VALIDATED: (True, True),
            ValidationStatus.NOT_CONFIRMED: (True, False),
            ValidationStatus.SANDBOX_ERROR: (True, False),
            ValidationStatus.TIMEOUT: (True, False),
            ValidationStatus.INVALID_HYPOTHESIS: (False, False),
            ValidationStatus.PREFLIGHT_ERROR: (False, False),
        }

        expected_attempted, expected_confirmed = invariants[status]
        if attempted_val != expected_attempted or confirmed_val != expected_confirmed:
            return ValidationResult(
                hypothesis_id=hypothesis.id,
                status=ValidationStatus.SANDBOX_ERROR,
                attempted=True,
                confirmed=False,
                error_message=(
                    f"Sandbox response violates state invariants for status '{status.value}': "
                    f"attempted={attempted_val} (expected {expected_attempted}), "
                    f"confirmed={confirmed_val} (expected {expected_confirmed})"
                )
            )

        return ValidationResult(
            hypothesis_id=hypothesis.id,
            status=status,
            attempted=attempted_val,
            confirmed=confirmed_val,
            confidence_delta=float(conf_delta_val),
            evidence=evidence_val,
            stdout=stdout_val,
            stderr=stderr_val,
            duration=duration_val,
            error_message=err_msg_val,
            metadata=metadata_val
        )

    def _execute_local_sandbox(
        self,
        hypothesis: SecurityHypothesis,
        repository_context: RepositoryReport,
        runner_path: str,
        cancellation_event: Optional[threading.Event] = None
    ) -> ValidationResult:
        """Spawns an isolated Python subprocess sandbox runner to validate codebase."""
        payload = {
            "hypothesis": self._to_canonical_dict(hypothesis),
            "report": self._to_canonical_dict(repository_context),
            "authoritative_repo_root": os.path.abspath(repository_context.repository.root),
            "config": {
                "max_evidence_file_bytes": getattr(self, "max_evidence_file_bytes", 10 * 1024 * 1024)
            }
        }
        json_input = json.dumps(payload)

        repo_path = os.path.abspath(repository_context.repository.root)

        backend = SubprocessSandboxBackend(self._reader_thread)
        return self._execute_sandbox(backend, hypothesis, json_input, runner_path, repo_path, cancellation_event)

    def _execute_container_sandbox(
        self,
        hypothesis: SecurityHypothesis,
        repository_context: RepositoryReport,
        runner_path: str,
        cancellation_event: Optional[threading.Event] = None
    ) -> ValidationResult:
        """Spawns an isolated Docker container sandbox runner to validate codebase."""
        payload = {
            "hypothesis": self._to_canonical_dict(hypothesis),
            "report": self._to_canonical_dict(repository_context),
            "authoritative_repo_root": "/workspace",
            "config": {
                "max_evidence_file_bytes": getattr(self, "max_evidence_file_bytes", 10 * 1024 * 1024)
            }
        }
        # Enforce that repository root is set to /workspace inside the container
        payload["report"]["repository"]["root"] = "/workspace"
        json_input = json.dumps(payload)

        repo_path = os.path.abspath(repository_context.repository.root)

        backend = DockerSandboxBackend(self._reader_thread, image_name=self.image_name)
        return self._execute_sandbox(backend, hypothesis, json_input, runner_path, repo_path, cancellation_event)

    def validate(
        self,
        hypothesis: SecurityHypothesis,
        repository_context: RepositoryReport,
        cancellation_event: Optional[threading.Event] = None
    ) -> ValidationResult:
        """Executes verification inside the TrueForge container workspace."""
        # Safety/Preflight checks: Enforce fail-closed for sandbox configuration errors
        if not self.local_sandbox and not self.container_sandbox and not self.api_key:
            return ValidationResult(
                hypothesis_id=hypothesis.id,
                status=ValidationStatus.PREFLIGHT_ERROR,
                attempted=False,
                confirmed=False,
                error_message="Sandbox configuration error: Missing TRUEFORGE_API_KEY"
            )

        # 1. Authoritative runner path resolution (CWD-independent)
        try:
            current_dir = os.path.dirname(os.path.abspath(__file__))
            runner_path = os.path.abspath(os.path.realpath(os.path.join(current_dir, "sandbox_runner.py")))

            if not (os.path.exists(runner_path) and os.path.isfile(runner_path)):
                import breakglass.validation.sandbox_runner as sandbox_runner
                runner_path = os.path.abspath(os.path.realpath(sandbox_runner.__file__))
                if runner_path.endswith('.pyc'):
                    runner_path = runner_path[:-1]

            # Verify file exists and is a regular file
            if not (os.path.exists(runner_path) and os.path.isfile(runner_path)):
                return ValidationResult(
                    hypothesis_id=hypothesis.id,
                    status=ValidationStatus.PREFLIGHT_ERROR,
                    attempted=False,
                    confirmed=False,
                    error_message=f"Preflight error: Sandbox runner not found at {runner_path}"
                )
        except Exception as e:
            return ValidationResult(
                hypothesis_id=hypothesis.id,
                status=ValidationStatus.PREFLIGHT_ERROR,
                attempted=False,
                confirmed=False,
                error_message=f"Preflight error: Failed to resolve sandbox runner path: {str(e)}"
            )

        # Dispatch execution
        if self.container_sandbox:
            return self._execute_container_sandbox(hypothesis, repository_context, runner_path, cancellation_event)
        elif self.local_sandbox:
            return self._execute_local_sandbox(hypothesis, repository_context, runner_path, cancellation_event)

        # Remote API orchestration mode placeholder:
        return ValidationResult(
            hypothesis_id=hypothesis.id,
            status=ValidationStatus.NOT_ATTEMPTED,
            attempted=False,
            confirmed=False,
            confidence_delta=0.0,
            evidence="TrueForge remote validation configured. Remote orchestration not executed in this environment.",
            error_message="Remote sandbox execution deferred.",
            metadata={"endpoint": self.endpoint}
        )

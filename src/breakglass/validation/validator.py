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
        repository_context: RepositoryReport
    ) -> ValidationResult:
        """Validates a SecurityHypothesis inside a sandboxed environment.

        Args:
            hypothesis: The hypothesis to validate.
            repository_context: The authoritative codebase report.

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
        repository_context: RepositoryReport
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


class TrueForgeSandboxValidator(SandboxValidator):
    """Adapter boundary for the TrueForge execution sandbox."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        endpoint: Optional[str] = None,
        local_sandbox: bool = False,
        timeout_seconds: Optional[float] = None,
        max_output_bytes: Optional[int] = None
    ):
        # Read from environment variables if not provided
        self.api_key = api_key or os.environ.get("TRUEFORGE_API_KEY")
        self.endpoint = endpoint or os.environ.get("TRUEFORGE_ENDPOINT", "https://api.trueforge.example.com")
        self.local_sandbox = local_sandbox or (os.environ.get("TRUEFORGE_LOCAL_SANDBOX") == "true")

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
        proc: subprocess.Popen,
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

    def _execute_local_sandbox(
        self,
        hypothesis: SecurityHypothesis,
        repository_context: RepositoryReport
    ) -> ValidationResult:
        """Spawns an isolated Python subprocess sandbox runner to validate codebase."""
        # 1. Construct serialized request payload strictly from authoritative data
        payload = {
            "hypothesis": self._to_canonical_dict(hypothesis),
            "report": self._to_canonical_dict(repository_context)
        }
        json_input = json.dumps(payload)

        # 2. Run runner module in separate Python process with configured environment path
        cmd = [sys.executable, "-m", "breakglass.validation.sandbox_runner"]
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
            return ValidationResult(
                hypothesis_id=hypothesis.id,
                status=ValidationStatus.SANDBOX_ERROR,
                attempted=True,
                confirmed=False,
                error_message=f"Failed to spawn sandbox subprocess: {str(e)}"
            )

        # 3. Use thread readers and non-blocking writer to actively enforce combined limits
        max_q_size = max(5, self.max_output_bytes // 1024 + 2)
        q_out = queue.Queue(maxsize=max_q_size)
        q_err = queue.Queue(maxsize=max_q_size)

        counter = _CombinedOutputCounter(self.max_output_bytes)
        overflow_event = threading.Event()
        shutdown_event = threading.Event()

        t_out = threading.Thread(
            target=self._reader_thread,
            args=(proc.stdout, q_out, counter, proc, overflow_event, shutdown_event),
            daemon=True
        )
        t_err = threading.Thread(
            target=self._reader_thread,
            args=(proc.stderr, q_err, counter, proc, overflow_event, shutdown_event),
            daemon=True
        )
        t_out.start()
        t_err.start()

        # Send input via background non-blocking writer thread to avoid pipe buffer deadlocks
        t_in = threading.Thread(target=self._writer_thread, args=(proc.stdin, json_input), daemon=True)
        t_in.start()

        stdout_chunks = []
        stderr_chunks = []

        timeout_hit = False
        overflow_hit = False

        while True:
            # Drain stdout
            while not q_out.empty():
                try:
                    chunk = q_out.get_nowait()
                    stdout_chunks.append(chunk)
                except queue.Empty:
                    break

            # Drain stderr
            while not q_err.empty():
                try:
                    chunk = q_err.get_nowait()
                    stderr_chunks.append(chunk)
                except queue.Empty:
                    break

            if overflow_event.is_set():
                overflow_hit = True
                break

            if time.perf_counter() - start_time > self.timeout_seconds:
                timeout_hit = True
                break

            ret = proc.poll()
            if ret is not None:
                break

            time.sleep(0.01)

        duration = time.perf_counter() - start_time

        # Clean up subprocess securely (fail closed)
        if overflow_hit or timeout_hit:
            shutdown_event.set()
            if not overflow_hit:
                try:
                    proc.kill()
                except Exception:
                    pass
            proc.wait()
            try:
                proc.stdout.close()
                proc.stderr.close()
            except Exception:
                pass

            if overflow_hit:
                return ValidationResult(
                    hypothesis_id=hypothesis.id,
                    status=ValidationStatus.SANDBOX_ERROR,
                    attempted=True,
                    confirmed=False,
                    error_message=f"Sandbox execution aborted: combined output size exceeded limit of {self.max_output_bytes} bytes"
                )
            else:
                return ValidationResult(
                    hypothesis_id=hypothesis.id,
                    status=ValidationStatus.TIMEOUT,
                    attempted=True,
                    confirmed=False,
                    error_message=f"Sandbox execution timed out after {self.timeout_seconds} seconds"
                )

        # Wait for the process to exit completely and drain the queues
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

        stdout_data = "".join(stdout_chunks)
        stderr_data = "".join(stderr_chunks)

        try:
            proc.stdout.close()
            proc.stderr.close()
        except Exception:
            pass

        if proc.returncode != 0:
            return ValidationResult(
                hypothesis_id=hypothesis.id,
                status=ValidationStatus.SANDBOX_ERROR,
                attempted=True,
                confirmed=False,
                error_message=f"Sandbox process exited with code {proc.returncode}. Stderr: {stderr_data.strip()}"
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

    def validate(
        self,
        hypothesis: SecurityHypothesis,
        repository_context: RepositoryReport
    ) -> ValidationResult:
        """Executes verification inside the TrueForge container workspace."""
        # Safety/Preflight checks: Enforce fail-closed for sandbox configuration errors
        if not self.local_sandbox and not self.api_key:
            return ValidationResult(
                hypothesis_id=hypothesis.id,
                status=ValidationStatus.PREFLIGHT_ERROR,
                attempted=False,
                confirmed=False,
                error_message="Sandbox configuration error: Missing TRUEFORGE_API_KEY"
            )

        # Dispatch execution
        if self.local_sandbox:
            return self._execute_local_sandbox(hypothesis, repository_context)

        # Remote API orchestration mode placeholder:
        # Does NOT return VALIDATED/confirmed=True (Finding 1 fix)
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

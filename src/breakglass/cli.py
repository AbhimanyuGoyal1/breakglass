"""Command-line interface (CLI) for the BREAKGLASS assessment agent."""

import argparse
import json
import os
import sys
import traceback
from breakglass import (
    inspect_repository,
    DeterministicReasoningEngine,
    LLMReasoningEngine,
    GeminiLLMClient,
    MockSandboxValidator,
    TrueForgeSandboxValidator,
    ValidationConfig,
    ValidationEngine,
    ValidationStatus
)


def print_header(title: str):
    print("=" * 60)
    print(f" {title}")
    print("=" * 60)


def main():
    parser = argparse.ArgumentParser(
        description="BREAKGLASS: Autonomous red-team security assessment and hypothesis validation agent."
    )
    parser.add_argument(
        "target_path",
        help="Local directory path of the target repository to inspect."
    )
    parser.add_argument(
        "--output", "-o",
        help="Output JSON file path to write the structured assessment report."
    )
    parser.add_argument(
        "--llm",
        action="store_true",
        help="Enable LLM-assisted reasoning using Google Gemini."
    )
    parser.add_argument(
        "--validate",
        action="store_true",
        help="Enable sandbox validation of eligible hypotheses."
    )
    parser.add_argument(
        "--validator",
        choices=["mock", "local", "container", "trueforge"],
        default="mock",
        help="Sandbox validator backend selection (default: mock)."
    )
    parser.add_argument(
        "--max-hypotheses",
        type=int,
        default=10,
        help="Maximum number of hypotheses to validate in a single run (default: 10)."
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=30.0,
        help="Timeout in seconds for validation execution (default: 30.0)."
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose logging."
    )

    args = parser.parse_args()

    # 1. Target path resolution and safety check
    target_abs = os.path.abspath(args.target_path)
    if not os.path.exists(target_abs):
        print(f"Error: Target path does not exist: {target_abs}", file=sys.stderr)
        sys.exit(1)
    if not os.path.isdir(target_abs):
        print(f"Error: Target path is not a directory: {target_abs}", file=sys.stderr)
        sys.exit(1)

    if args.verbose:
        print(f"[*] Starting BREAKGLASS run on repository: {target_abs}")

    try:
        # 2. Ingest and Inspect Repository
        if args.verbose:
            print("[*] Performing static code inspection...")
        report = inspect_repository(target_abs)

        print_header("REPOSITORY INGESTION & INSPECTION SUMMARY")
        print(f"Root: {report.repository.root}")
        print(f"Files: {report.repository.total_files} | Directories: {report.repository.total_directories}")
        print(f"Languages: {', '.join(report.repository.languages.keys()) or 'None'}")
        print(f"Frameworks: {', '.join(report.repository.frameworks) or 'None'}")
        print(f"Security Indicators Extracted: {len(report.security_indicators)}")
        print(f"Routes Discovered: {len(report.routes)}")
        print(f"Entry Points Discovered: {len(report.entry_points)}")
        print()

        # 3. Reasoning Layer
        if args.verbose:
            print("[*] Generating hypotheses using deterministic reasoning...")
        det_engine = DeterministicReasoningEngine()
        reasoning_report = det_engine.generate_hypotheses(report)

        if args.llm:
            if args.verbose:
                print("[*] Extending hypotheses using LLM-assisted reasoning...")
            try:
                client = GeminiLLMClient()
                llm_engine = LLMReasoningEngine(client)
                reasoning_report = llm_engine.analyze(report, reasoning_report)
                if reasoning_report.validation_status == "failed":
                    print(f"Warning: LLM-assisted reasoning failed to validate: {', '.join(reasoning_report.errors)}")
            except Exception as e:
                print(f"Error initializing or executing LLM engine: {str(e)}", file=sys.stderr)
                sys.exit(1)

        print_header("SECURITY HYPOTHESES GENERATED")
        print(f"Total Hypotheses: {len(reasoning_report.hypotheses)}")
        for i, hyp in enumerate(reasoning_report.hypotheses, start=1):
            print(f"{i}. [{hyp.id}] ({hyp.severity}) {hyp.title}")
            print(f"   Category: {hyp.category} | Confidence: {hyp.confidence}")
            print(f"   Rationale: {hyp.rationale}")
            print(f"   Evidence References ({len(hyp.evidence_references)}):")
            for ref in hyp.evidence_references:
                line_str = f":L{ref.line}" if ref.line is not None else ""
                print(f"     - [{ref.type}] {ref.file}{line_str} -> {ref.detail}")
        print()

        # 4. Validation Layer
        validation_results = []
        if args.validate:
            if args.verbose:
                print(f"[*] Initializing sandbox validator: {args.validator}...")

            # Select sandbox backend
            if args.validator == "mock":
                validator = MockSandboxValidator()
            elif args.validator == "local":
                validator = TrueForgeSandboxValidator(local_sandbox=True)
            elif args.validator == "container":
                validator = TrueForgeSandboxValidator(container_sandbox=True)
            elif args.validator == "trueforge":
                # API orchestration mode
                validator = TrueForgeSandboxValidator()
                if not validator.api_key:
                    print("Error: TRUEFORGE_API_KEY environment variable is required for API validation mode.", file=sys.stderr)
                    sys.exit(1)
            else:
                validator = MockSandboxValidator()

            try:
                config = ValidationConfig(
                    timeout_seconds=args.timeout,
                    max_hypotheses_per_run=args.max_hypotheses
                )
                validation_engine = ValidationEngine(validator, config)
                if args.verbose:
                    print("[*] Running sandbox validation on eligible hypotheses...")
                validation_results = validation_engine.validate_hypotheses(reasoning_report.hypotheses, report)
            except Exception as e:
                print(f"Error during validation orchestration: {str(e)}", file=sys.stderr)
                sys.exit(1)

            print_header("SANDBOX HYPOTHESIS VALIDATION RESULTS")
            for res in validation_results:
                print(f"Hypothesis: {res.hypothesis_id}")
                print(f"  Status: {res.status.value}")
                print(f"  Attempted: {res.attempted} | Confirmed: {res.confirmed}")
                if res.duration is not None:
                    print(f"  Duration: {res.duration:.3f}s")
                if res.error_message:
                    print(f"  Error: {res.error_message}")
                if res.evidence:
                    print(f"  Evidence: {res.evidence}")
            print()

        # 5. Output Serialization
        if args.output:
            output_data = {
                "repository": {
                    "root": report.repository.root,
                    "total_files": report.repository.total_files,
                    "languages": report.repository.languages,
                    "frameworks": report.repository.frameworks
                },
                "inspection_summary": {
                    "security_indicators": len(report.security_indicators),
                    "routes": len(report.routes),
                    "entry_points": len(report.entry_points)
                },
                "hypotheses": [hyp.to_dict() for hyp in reasoning_report.hypotheses],
                "validation_results": [res.to_dict() for res in validation_results],
                "metadata": {
                    "llm_enabled": args.llm,
                    "validation_enabled": args.validate,
                    "validator_type": args.validator if args.validate else None
                }
            }
            with open(args.output, "w", encoding="utf-8") as f:
                json.dump(output_data, f, indent=2)
            if args.verbose:
                print(f"[*] Structured assessment report written to: {args.output}")

        print("[+] BREAKGLASS assessment complete.")

    except Exception as e:
        print(f"Fatal error during execution: {str(e)}", file=sys.stderr)
        if args.verbose:
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()

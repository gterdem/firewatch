"""firewatch CLI — runtime entrypoint and developer tools for FireWatch.

Entry point: ``firewatch`` console script (pyproject.toml console_scripts).
Also invokable as ``python -m firewatch_cli.main`` for tests.

Subcommands
-----------
run
    Load plugins via entry points, start the supervisor (#22), and serve the
    API on a loopback bind (ADR-0026).  Blocks until SIGTERM/SIGINT.

sync --once
    Run one pull cycle per configured pull instance, then exit.  Exit code
    reflects success (0) or failure (1).  Admin/cron-friendly.

serve
    Serve the FireWatch API only (no supervisor loops).  For the UI-only demo.

new-source <name>
    Scaffold a new source-plugin package under packages/sources/<name>/.
    Options:
      --flavor pull|push     Pull (watermark-driven) or Push (listener) flavor.
                             Default: pull.
      --output-dir PATH      Root directory for output (default: cwd).
                             The package is created at <output-dir>/packages/sources/<name>/.

ai-baseline
    Operator verdict-drift CLI (MI-9 / issue #390).  Run the canonical AI
    scenarios against the configured local engine and compare verdicts.
    Options:
      --save [--out PATH]         Record current verdicts to a baseline file.
      --compare [--baseline PATH] Diff current verdicts vs. saved baseline;
                                  exits non-zero if any verdict drifted.
    Network: local endpoint only (ADR-0022).  Never runs in CI.
"""
from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

from firewatch_cli.scaffold import scaffold, validate_name


def _cmd_new_source(args: argparse.Namespace) -> int:
    """Handle the ``new-source`` subcommand. Returns exit code."""
    name: str = args.name
    flavor: str = args.flavor
    output_dir = Path(args.output_dir).resolve()

    # Validate name early so the error message is clean.
    try:
        validate_name(name)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    if flavor not in ("pull", "push"):
        print(
            f"Error: --flavor must be 'pull' or 'push', got {flavor!r}.",
            file=sys.stderr,
        )
        return 1

    try:
        pkg_root = scaffold(name, flavor=flavor, output_dir=output_dir)
    except FileExistsError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    print(f"Scaffolded '{name}' ({flavor} flavor) at:")
    print(f"  {pkg_root}")
    print()
    print("Next steps:")
    print(f"  1. Edit {pkg_root}/src/firewatch_{name}/normalize.py  — implement normalize()")
    print(f"  2. Edit {pkg_root}/src/firewatch_{name}/config.py     — add your config fields")
    if flavor == "pull":
        print(f"  3. Edit {pkg_root}/src/firewatch_{name}/collector.py — implement collect()")
    else:
        print(f"  3. Edit {pkg_root}/src/firewatch_{name}/listener.py  — implement the listener")
    print("  4. Add the package to the workspace pyproject.toml [tool.uv.sources] and")
    print("     [tool.uv.workspace] members (or run: uv sync).")
    print(f"  5. Run: uv run pytest {pkg_root}/tests/")
    print()
    print("The generated tests/test_plugin.py proves:")
    print("  - entry-point discovery (zero core edits)")
    print("  - SourcePlugin conformance")
    print("  - no forbidden imports (firewatch-sdk only)")
    print()
    print("See docs/module-author-guide.md for the full contributor guide.")
    return 0


def _cmd_run(args: argparse.Namespace) -> int:
    """Handle the ``run`` subcommand. Returns exit code."""
    # Deferred imports keep startup fast and avoid heavy dependencies when only
    # running ``firewatch new-source``.
    from firewatch_core.loader import load_source_plugins

    from firewatch_cli.commands.run import cmd_run

    config_file = Path(args.config).resolve() if hasattr(args, "config") and args.config else None

    registry = load_source_plugins()
    asyncio.run(
        cmd_run(
            registry=registry,
            config_file=config_file,
            host=args.host,
            port=args.port,
        )
    )
    return 0


def _cmd_sync(args: argparse.Namespace) -> int:
    """Handle the ``sync`` subcommand. Returns exit code."""
    if not args.once:
        print(
            "Error: only 'firewatch sync --once' is supported in MA "
            "(continuous sync is the supervisor's job).",
            file=sys.stderr,
        )
        return 1

    from firewatch_core.loader import load_source_plugins

    from firewatch_cli.commands.sync_once import cmd_sync_once

    config_file = Path(args.config).resolve() if hasattr(args, "config") and args.config else None

    registry = load_source_plugins()
    exit_code: int = asyncio.run(
        cmd_sync_once(registry=registry, config_file=config_file)
    )
    return exit_code


def _cmd_serve(args: argparse.Namespace) -> int:
    """Handle the ``serve`` subcommand. Returns exit code."""
    from firewatch_core.loader import load_source_plugins

    from firewatch_cli.commands.serve import cmd_serve

    registry = load_source_plugins()
    cmd_serve(registry=registry, host=args.host, port=args.port)
    return 0


def _cmd_ai_baseline(args: argparse.Namespace) -> int:
    """Handle the ``ai-baseline`` subcommand. Returns exit code."""
    from firewatch_core.adapters.ai_openai import OpenAIEngine
    from firewatch_core.config_store import JsonFileConfigStore

    from firewatch_cli.commands.ai_baseline import cmd_ai_baseline

    config_file = Path(args.config).resolve() if hasattr(args, "config") and args.config else None
    runtime = JsonFileConfigStore(config_file=config_file).get_runtime()

    if not runtime.ai_enabled:
        print(
            "Error: ai_enabled is false in config — cannot run ai-baseline.\n"
            "Set ai_enabled=true and configure ollama_base_url/ollama_model first.",
            file=sys.stderr,
        )
        return 1

    try:
        engine = OpenAIEngine(
            base_url=runtime.ollama_base_url,
            model=runtime.ollama_model,
        )
    except Exception as exc:
        print(
            f"Error: could not build AI engine — {exc}\n"
            "Check that ollama_base_url points to a local inference endpoint (ADR-0022).",
            file=sys.stderr,
        )
        return 1

    mode = "save" if args.save else "compare"
    out_path = Path(args.out).resolve() if getattr(args, "out", None) else None
    baseline_path = Path(args.baseline).resolve() if getattr(args, "baseline", None) else None
    report_out = Path(args.report_out).resolve() if getattr(args, "report_out", None) else None

    return asyncio.run(
        cmd_ai_baseline(
            mode=mode,
            engine=engine,
            out_path=out_path,
            baseline_path=baseline_path,
            report_out=report_out,
        )
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="firewatch",
        description=(
            "FireWatch network-monitoring platform. "
            "Runtime entry point and developer tools."
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # ------------------------------------------------------------------ #
    # run subcommand                                                       #
    # ------------------------------------------------------------------ #
    run_p = sub.add_parser(
        "run",
        help="Load plugins, start the supervisor, and serve the API (loopback).",
        description=(
            "Load source plugins via entry points, start the collector supervisor "
            "(ADR-0023), and serve the FireWatch REST API on a loopback bind "
            "(ADR-0026).  Blocks until SIGTERM/SIGINT triggers a bounded graceful "
            "shutdown."
        ),
    )
    run_p.add_argument(
        "--host",
        default="127.0.0.1",
        help="API bind address (default: 127.0.0.1 — loopback only, ADR-0026).",
    )
    run_p.add_argument(
        "--port",
        type=int,
        default=8000,
        help="API listen port (default: 8000).",
    )
    run_p.add_argument(
        "--config",
        default=None,
        metavar="PATH",
        help=(
            "Path to firewatch_config.json "
            "(default: firewatch_config.json in the current directory)."
        ),
    )

    # ------------------------------------------------------------------ #
    # sync subcommand                                                      #
    # ------------------------------------------------------------------ #
    sync_p = sub.add_parser(
        "sync",
        help="Run a one-shot pull cycle for each configured instance.",
        description=(
            "Run exactly one pull cycle for each configured pull instance, then exit. "
            "Suitable for cron / admin use.  Pass --once (the only supported mode in MA)."
        ),
    )
    sync_p.add_argument(
        "--once",
        action="store_true",
        default=False,
        help="Run a single pull cycle and exit (required in MA).",
    )
    sync_p.add_argument(
        "--config",
        default=None,
        metavar="PATH",
        help="Path to firewatch_config.json (default: cwd).",
    )

    # ------------------------------------------------------------------ #
    # serve subcommand                                                     #
    # ------------------------------------------------------------------ #
    serve_p = sub.add_parser(
        "serve",
        help="Serve the FireWatch API only (no supervisor loops).",
        description=(
            "Start the FireWatch REST API without any supervisor or collector loops. "
            "Useful for the UI-only demo or when the supervisor runs separately."
        ),
    )
    serve_p.add_argument(
        "--host",
        default="127.0.0.1",
        help="API bind address (default: 127.0.0.1 — loopback only, ADR-0026).",
    )
    serve_p.add_argument(
        "--port",
        type=int,
        default=8000,
        help="API listen port (default: 8000).",
    )

    # ------------------------------------------------------------------ #
    # new-source subcommand                                                #
    # ------------------------------------------------------------------ #
    ns = sub.add_parser(
        "new-source",
        help="Scaffold a new FireWatch source-plugin package.",
        description=(
            "Generate a ready-to-edit plugin package under "
            "packages/sources/<name>/. The generated package depends on "
            "firewatch-sdk only and is discoverable by the loader with zero "
            "core edits."
        ),
    )
    ns.add_argument(
        "name",
        help=(
            "Source type key — must match ^[a-z][a-z0-9_]*$ (must start with a "
            "lowercase letter; digits and underscores may follow). "
            "Examples: azure_waf, mywidget, syslog2."
        ),
    )
    ns.add_argument(
        "--flavor",
        choices=["pull", "push"],
        default="pull",
        help=(
            "Plugin flavor: 'pull' (watermark-driven collector, e.g. Suricata) or "
            "'push' (listener, e.g. Syslog UDP/TCP). Default: pull."
        ),
    )
    ns.add_argument(
        "--output-dir",
        default=".",
        metavar="PATH",
        help=(
            "Root directory for output. The package is created at "
            "<output-dir>/packages/sources/<name>/. Default: current directory."
        ),
    )

    # ------------------------------------------------------------------ #
    # ai-baseline subcommand (MI-9 / issue #390)                          #
    # ------------------------------------------------------------------ #
    ab = sub.add_parser(
        "ai-baseline",
        help="Operator verdict-drift CLI — detect model drift against a saved baseline.",
        description=(
            "Run the canonical AI scenario fixtures against the configured local "
            "inference endpoint and compare the verdicts (threat_level, "
            "recommended_action, attack_stage) against a previously saved baseline.\n\n"
            "Use --save to record a baseline after verifying your model behaves "
            "correctly.  Use --compare to detect drift after a model upgrade.\n\n"
            "Network: local endpoint only (ADR-0022).  Never use as a CI gate."
        ),
    )
    # Mode: exactly one of --save or --compare must be given.
    ab_mode = ab.add_mutually_exclusive_group(required=True)
    ab_mode.add_argument(
        "--save",
        action="store_true",
        default=False,
        help="Run scenarios and save verdicts to --out (or firewatch_verdict_baseline.json).",
    )
    ab_mode.add_argument(
        "--compare",
        action="store_true",
        default=False,
        help=(
            "Re-run scenarios and compare against --baseline. "
            "Exits non-zero if any verdict drifted."
        ),
    )
    ab.add_argument(
        "--out",
        default=None,
        metavar="PATH",
        help=(
            "Output path for --save (default: firewatch_verdict_baseline.json "
            "in the current directory)."
        ),
    )
    ab.add_argument(
        "--baseline",
        default=None,
        metavar="PATH",
        help=(
            "Baseline file for --compare "
            "(default: firewatch_verdict_baseline.json in the current directory)."
        ),
    )
    ab.add_argument(
        "--report-out",
        default=None,
        metavar="PATH",
        dest="report_out",
        help=(
            "Output path for the machine-readable drift report JSON (--compare only). "
            "Defaults to firewatch_drift_report.json alongside the baseline file. "
            "The report is read by GET /ai/baseline/drift."
        ),
    )
    ab.add_argument(
        "--config",
        default=None,
        metavar="PATH",
        help="Path to firewatch_config.json (used to read ollama_base_url/model/ai_enabled).",
    )

    return parser


def main(argv: list[str] | None = None) -> None:
    """Entry point for the ``firewatch`` console script."""
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "new-source":
        sys.exit(_cmd_new_source(args))
    elif args.command == "run":
        sys.exit(_cmd_run(args))
    elif args.command == "sync":
        sys.exit(_cmd_sync(args))
    elif args.command == "serve":
        sys.exit(_cmd_serve(args))
    elif args.command == "ai-baseline":
        sys.exit(_cmd_ai_baseline(args))
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()

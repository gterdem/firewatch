"""firewatch_cli.commands — runtime subcommand implementations.

Each module in this subpackage handles exactly one subcommand:

  run       — load plugins, start supervisor, serve API (loopback).
  sync_once — single pull cycle per configured instance, then exit.
  serve     — API only, no supervisor (UI-only demo).

All modules keep themselves thin: argument parsing stays in ``main.py``;
real logic delegates to ``firewatch_core`` (supervisor, pipeline, loader).
"""

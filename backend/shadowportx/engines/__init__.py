"""ShadowPortX engines: recon, scanner, verification, intel, correlation, risk, reporting.

Each engine is independent and operates on plain dataclasses (``engines.results``),
so they can be unit-tested in isolation and composed by the scan orchestrator.
"""

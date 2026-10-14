"""CyberRescue evaluation — measure detection against ground truth (EVALUATION ONLY).

This is the only package that may read ``datasets/.../ground_truth/``. It runs
the operational pipeline (telemetry import -> evidence -> detection, dry run)
in a throw-away Core, then joins the detection report with the scenario's
labels by ``evidence.source_ref == event_id``. Nothing here is imported by the
Core, the telemetry importer or the detection engine.

Measured per scenario — deliberately no single accuracy number:
stage coverage, expected / unexpected findings, evidence coverage and
precision, fact checks against ``facts``, observations, and the per-rule matrix.
"""

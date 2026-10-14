"""Live-mode support for the WarRoom four-agent runtime (CA3 preparation).

* ``preflight``   - offline readiness check: interpreter, packages, credentials
                    (presence only, never values), agent_config.yaml, agent module
                    imports, Commander-gate settings. No network, no LLM calls.
* ``roster``      - build the trusted Band-id -> Core-role roster for
                    ``core import-band`` from agent_config.yaml.
* ``band_export`` - read-only export of a Band room into the JSON context shape
                    that ``core import-band`` consumes (network only when run).

Nothing here substitutes mock agents for real ones, creates approvals, or
changes how the Commander gate decides.
"""

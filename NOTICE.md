# Notice

## Upstream project

CyberRescue-AI is built on **WarRoom** by **George**:

- Upstream repository: <https://github.com/genyarko/warroom>
- Upstream commits are authored as "George" (GitHub account `merolavtechnologies`),
  dated 2026-06-13 to 2026-06-15. The upstream baseline is commit `e5c11bc`.

The four-agent architecture originates substantially from upstream: the Triage,
Threat Intel, Compliance and Commander agents (`agents/`), their prompts and domain
tools, the Band protocol and message schema (`shared/protocol.md`,
`shared/schemas.py`), the mock environment (`shared/mock_env/`), the Band SDK
patches (`shared/sdk_patches.py`), the launcher (`scripts/run_all.ps1`), the
Facilitator (`scripts/incident_driver.py`), the exporters, the injector, the
Docker files and the original 77-test suite. The upstream agent prompts are kept
verbatim, including the upstream author's Band handles.

Some upstream files were later modified for CyberRescue-AI. Each modification is
listed in [docs/ca3/11-contribution-attribution.md](docs/ca3/11-contribution-attribution.md).

## CyberRescue-AI extensions

The `cyberrescue/` packages, their tests, `scripts/demo_offline.ps1`,
`scripts/Resolve-RepoPython.ps1`, `tests_live/` and `docs/ca3/` were added by
Mourno12 with substantial AI assistance from Claude Code, which was used for
implementation, testing, debugging and documentation. This code was not written
independently by Mourno12; see
[docs/ca3/11-contribution-attribution.md](docs/ca3/11-contribution-attribution.md).

## License status

As of 2026-10-14, neither this repository nor the upstream WarRoom repository
contains a license file. This notice grants no license and does not imply one.
Rights in the upstream WarRoom code remain with its author.

## History

This repository contains a single snapshot commit. It does not contain the
original development history. That history, including every upstream commit with
its original authorship and every `Co-Authored-By` trailer, is preserved
unchanged in the **original repository**, https://github.com/Mourno12/-CyberRescue-AI (branch
`cyberrescue-ai`, last commit `ebdfa24`), referred to below and in `docs/ca3/` as
the archived history. The upstream history is also available in the upstream
repository. Commit hashes cited in `docs/ca3/` refer to the archived history and
do not exist in this repository.

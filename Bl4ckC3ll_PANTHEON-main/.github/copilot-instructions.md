# Copilot coding agent: Bl4ckC3ll_PANTHEON

Purpose: Give AI agents the minimal-but-sufficient context to be productive in this repo. Keep changes safe, testable, and aligned with existing patterns.

## Big picture
- This is a Python-based offensive security orchestrator intended for authorized testing only.
- Two primary entry points:
  - `bl4ckc3ll_p4nth30n.py` — production-hardened, “clean” orchestrator (recon + vuln scan + report + plugins).
  - `bl4ckc3ll_pantheon_master.py` — consolidated CLI/TUI “master” app that wraps core features and adds UX and demos.
- Scans integrate external tools (nuclei, subfinder, httpx, naabu, ffuf, amass, etc.). Tools are optional; code must degrade gracefully when missing.
- Outputs are written per run under `runs/<run-id>/` with subfolders for `recon/`, `vuln_scan/`, and `report/`; logs land in `logs/`.
- Config is generated at first run (`p4nth30n.cfg.json`); defaults live in `DEFAULT_CFG` inside `bl4ckc3ll_p4nth30n.py`.

## Architecture & data flow (what matters to contributors)
- Orchestrator controls pipeline stages and invokes external tools via safe wrappers. Key helpers in `bl4ckc3ll_p4nth30n.py`:
  - Input safety: `validate_input`, `validate_domain_input`, `validate_ip_input`, `validate_url_input`.
  - Command safety: `safe_run_command(...)` and `execute_tool_safely(tool, args, timeout, output_file)` — prefer these over raw `subprocess`.
  - IO: `atomic_write(path, data)` for durable writes; `read_lines(path)` for inputs like `targets.txt`.
  - Logging: use `logger.log(msg, level)` (or `PantheonLogger` in the master app) instead of `print` for pipeline code.
  - Path constants: `RUNS_DIR`, `LOG_DIR`, `PLUGINS_DIR`, `MERGED_DIR`, etc. Use them instead of hard-coded paths.
- Nuclei templates are managed/enriched via `EnhancedNucleiManager` (update, stats, and custom templates under `nuclei-templates/custom/`).
- Plugins live in `plugins/`. Contract:
  - Each plugin exports `plugin_info: dict` and `def execute(run_dir: Path, env: Dict[str, str], cfg: Dict[str, Any])`.
  - See `plugins/advanced_osint.py` for a concrete example (reads `targets.txt`, writes results under `run_dir`).

## Developer workflows
- Quick start (installs tools, creates targets, runs app): `./quickstart.sh`.
- Make targets (preferred for common ops): `make help`, `make quickstart`, `make run`, `make diagnostics`, `make update`, `make clean`.
- Run locally:
  - Orchestrator: `python3 bl4ckc3ll_p4nth30n.py` (interactive menu and presets).
  - Master CLI/TUI: `python3 bl4ckc3ll_pantheon_master.py` or `--tui` or `--target <domain>` for a quick scan.
- Tests (ad hoc, tolerant to missing external tools):
  - `python3 enhanced_test_suite.py`
  - `python3 test_automation_integration.py`
  - `python3 final_integration_test.py`
- JavaScript lint/security checks (for supporting assets): `npm run lint:check` and `npm run lint:security` (see `package.json`).
- Docker: `Dockerfile` builds a full toolchain image; CI uses `.github/workflows/security_scan.yml` with `target` and `scan_type` inputs.

## Project conventions (follow these when adding/changing code)
- Always validate inputs and route external commands through `safe_run_command` or `execute_tool_safely` (never raw `subprocess.run` in new code).
- Write files with `atomic_write`; place run artifacts under the current run directory (`new_run()` typically sets this up) and logs under `logs/`.
- Check tool availability first (e.g., `which(tool)` is used inside `execute_tool_safely`); if missing, log a warning and continue.
- Keep outputs deterministic and parse-friendly (JSON/CSV/HTML in `report/`); avoid interactive prompts in non-interactive paths.
- Respect resource limits; prefer existing rate-limiting and timeouts (`RateLimiter`, `safe_http_request`, config limits under `DEFAULT_CFG`).
- Use the existing logger(s) and avoid noisy prints; INFO logs summarize stages, DEBUG contains command details.

## Common tasks for AI changes (how to do them “the repo way”)
- Add a new plugin:
  1) Create `plugins/<name>.py` with `plugin_info` and `execute(run_dir, env, cfg)`.
  2) Read targets from `targets.txt` with `read_lines`; write JSON to `run_dir/<your_module>/...` via `atomic_write`.
  3) Wrap tool calls with `execute_tool_safely` and guard for missing tools.
- Extend scanning with a preset:
  - Update `ScanPresets.SCAN_PRESETS` in `bl4ckc3ll_p4nth30n.py`; reuse existing stage functions (e.g., `stage_recon`, `stage_vuln_scan`).
- Enhance nuclei coverage:
  - Add templates under `nuclei-templates/custom/` and wire via `EnhancedNucleiManager.create_custom_nuclei_templates()`.

## Integration points
- CI workflow: `.github/workflows/security_scan.yml` runs ESLint, optional bug bounty automation, and `cicd_integration.py`, uploads SARIF/JSON.
- External tools: ProjectDiscovery suite, sqlmap, ffuf, waybackurls, gospider, etc. PATH is bumped at runtime (`_bump_path()`); code skips tools gracefully.

## Pitfalls and tips
- Tests include some optional/aspirational checks; don’t remove/rename public helpers used across files.
- Avoid hard-coding system paths; respect `DEFAULT_CFG` and write under `runs/<run-id>/`.
- Network calls must have timeouts and polite headers (see `safe_http_request`).

Questions or gaps? Open an issue or ask which preset/plugin to extend; we’ll iterate and refine these instructions.

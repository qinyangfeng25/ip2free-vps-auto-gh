# Code Review Notes

This GitHub copy is a sanitized publishable version of the project. The local
runtime data such as proxy state, DNS resolution caches, logs, credentials, and
private virtual environments are excluded via `.gitignore`.

## Public-copy cleanup applied

- Removed the local `.venv` directory from the copied tree.
- Replaced the committed panel password with an empty value.
- Removed the local absolute log path from `panel_config.json` and changed it to
  `data/panel.log`.
- Replaced cached domain resolution data with placeholder values.
- Replaced the local panel log with an empty placeholder file.
- Added startup-time credential generation: if no panel password is configured,
  the panel creates one and prints it on startup.

## Code review findings

- `install.sh` previously deployed only the agent files, so the Flask panel would
  not run after a fresh install. It now copies the panel, templates, static files,
  `panel_config.json`, and `requirements.txt`.
- Runtime data files are excluded from version control to avoid leaking logs,
  resolved IPs, proxy state, and credentials.
- Management credentials can now come from `panel_config.json`, environment
  variables, or first-run generation.

## Recommended follow-up before public release

- Prefer storing third-party credentials in `.env` or environment variables
  instead of JSON config.
- Bind the panel to `127.0.0.1` and expose it only through nginx or systemd
  socket activation.
- Use HTTPS or a reverse proxy for the management interface.
- Add unit tests for proxy parsing, DNS rule generation, and config loading.
- Replace static provider endpoints and user-agent strings if the upstream API
  changes.

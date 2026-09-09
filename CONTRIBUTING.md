# Contributing

Contributions should preserve SentinelForge's small, deterministic scope.

- Use Python standard-library features where practical.
- Add or update unittest coverage for behavior changes.
- Keep parser input bounded to documented fixture formats.
- Do not add offensive capabilities, network calls, secrets, or automated response.
- Run `python -m unittest discover -v` and `python -m compileall src` before submitting.
- Do not commit real authentication logs or other sensitive data.

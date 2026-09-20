# Contributing

1. Keep the privileged path free of raw untrusted text.
2. New detectors belong in `src/aetherwall/inspector/engine.py` plus a fixture
   under `examples/attacks/` and a test in `tests/`.
3. Policy language changes must compile through `aetherwall compile-policy`.
4. Do not add network-offensive tooling.

```bash
pip install -e ".[dev]"
pytest -q
aetherwall demo
```

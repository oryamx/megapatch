"""Loads an app.py from any folder, so the SAME PoC and tests can run against
the vulnerable code and against any patched copy."""
import importlib.util
from pathlib import Path


def load_app(app_dir):
    path = Path(app_dir) / "app.py"
    spec = importlib.util.spec_from_file_location("app_under_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.create_app()

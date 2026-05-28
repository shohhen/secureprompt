"""Compile every app/*.py (except __init__.py) into a C extension and strip
the original Python sources from disk so they do not ship in the runtime
image. Intended to run only inside the Docker builder stage."""
from __future__ import annotations

import shutil
import sys
from pathlib import Path

from Cython.Build import cythonize
from setuptools import setup

APP_DIR = Path(__file__).resolve().parent / "app"
BUILD_TEMP = Path("/tmp/cython_build")


def discover_sources() -> list[str]:
    sources: list[str] = []
    for path in sorted(APP_DIR.rglob("*.py")):
        if path.name == "__init__.py":
            continue
        sources.append(str(path))
    return sources


def compile_sources(sources: list[str]) -> None:
    BUILD_TEMP.mkdir(parents=True, exist_ok=True)
    ext_modules = cythonize(
        sources,
        language_level=3,
        compiler_directives={
            "binding": True,
            "embedsignature": True,
            "always_allow_keywords": True,
        },
        nthreads=4,
        quiet=False,
    )
    setup(
        name="secureprompt_ml_compiled",
        ext_modules=ext_modules,
        script_args=[
            "build_ext",
            "--inplace",
            "--build-temp",
            str(BUILD_TEMP),
        ],
    )


def strip_python_sources(sources: list[str]) -> None:
    for src in sources:
        Path(src).unlink(missing_ok=True)
    for c_file in APP_DIR.rglob("*.c"):
        c_file.unlink(missing_ok=True)
    for pycache in APP_DIR.rglob("__pycache__"):
        shutil.rmtree(pycache, ignore_errors=True)


def assert_clean() -> None:
    remaining = [
        p
        for p in APP_DIR.rglob("*.py")
        if p.name != "__init__.py"
    ]
    if remaining:
        sys.stderr.write(
            "Cython build left .py sources behind: "
            + ", ".join(str(p) for p in remaining)
            + "\n"
        )
        sys.exit(1)
    so_files = list(APP_DIR.rglob("*.so"))
    if not so_files:
        sys.stderr.write("Cython build produced no .so files\n")
        sys.exit(1)


def main() -> None:
    sources = discover_sources()
    if not sources:
        sys.stderr.write("No .py sources discovered under app/\n")
        sys.exit(1)
    compile_sources(sources)
    strip_python_sources(sources)
    assert_clean()


if __name__ == "__main__":
    main()

import re
import subprocess
import sys
from pathlib import Path


TASK_NAME = re.compile(rb'(g_task_set_name\s*\([^,\n]+,\s*")Frida\.')


def neutralize_task_names(source: bytes) -> bytes:
    return TASK_NAME.sub(rb'\g<1>Meshlink.', source)


def output_directory(arguments: list[str]) -> Path | None:
    for index, argument in enumerate(arguments):
        if argument == "--directory":
            return Path(arguments[index + 1])
        if argument.startswith("--directory="):
            return Path(argument.partition("=")[2])
    return None


def neutralize_directory(directory: Path) -> None:
    for generated in directory.rglob("*.c"):
        source = generated.read_bytes()
        updated = neutralize_task_names(source)
        if updated != source:
            generated.write_bytes(updated)


def main() -> int:
    compiler, *arguments = sys.argv[1:]
    result = subprocess.run([compiler, *arguments], check=False)
    if result.returncode != 0 or "-C" not in arguments:
        return result.returncode

    directory = output_directory(arguments)
    if directory is not None:
        neutralize_directory(directory)
    return 0


if __name__ == "__main__":
    sys.exit(main())

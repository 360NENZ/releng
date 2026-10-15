import re
import subprocess
import sys
from pathlib import Path


TASK_NAME = re.compile(rb'(g_task_set_name\s*\([^,\n]+,\s*")Frida\.')
TYPE_NAME = re.compile(
    rb'(\bg_(?:type_register_static(?:_simple)?|type_register_fundamental|enum_register_static|flags_register_static|'
    rb'boxed_type_register_static|pointer_type_register_static)\s*\([^;]*?")'
    rb'Frida([A-Z][A-Za-z0-9_]*")'
)
DBUS_PROXY = re.compile(
    rb'G_DEFINE_TYPE_EXTENDED \((Frida[A-Za-z0-9_]+Proxy), '
    rb'([a-z][a-z0-9_]+), G_TYPE_DBUS_PROXY,'
)
ERROR_DOMAIN = re.compile(
    rb'(\b(?:g_quark_from_static_string|g_dbus_error_register_error_domain)\s*\(\s*")'
    rb'frida(-(?:[a-z0-9]+-)*error-quark")'
)
ENUM_VALUES = re.compile(
    rb'(static const G(?:Enum|Flags)Value values\[\]\s*=\s*\{)([^;]*)(\};)',
    re.DOTALL,
)
ENUM_VALUE_NAME = re.compile(rb'"FRIDA_([A-Z0-9_]+)"')
SOURCE_LINE = re.compile(rb'(?m)^(#line\s+\d+\s+")([^"\r\n]+)(")$')
VALA_DIAGNOSTIC_FUNCTION = re.compile(
    rb'(?m)^(#define _vala_(?:assert|return_if_fail|return_val_if_fail|warn_if_fail)\([^\n]+?)G_STRFUNC'
)
ABSTRACT_METHOD_DIAGNOSTIC = re.compile(rb"(does not implement abstract method )`frida_[a-z0-9_]+'")


def neutralize_task_names(source: bytes) -> bytes:
    return TASK_NAME.sub(rb'\g<1>Meshlink.', source)


def neutralize_source_locations(source: bytes) -> bytes:
    return SOURCE_LINE.sub(lambda match: match[1] + match[2].replace(b"frida", b"meshlink") + match[3], source)


def neutralize_diagnostics(source: bytes) -> bytes:
    source = VALA_DIAGNOSTIC_FUNCTION.sub(rb'\g<1>"meshlink"', source)
    return ABSTRACT_METHOD_DIAGNOSTIC.sub(rb'\g<1>from this interface', source)


def neutralize_runtime_types(source: bytes) -> bytes:
    source = TYPE_NAME.sub(rb'\g<1>Meshlink\2', source)
    source = ERROR_DOMAIN.sub(rb'\g<1>meshlink\2', source)

    def rename_dbus_proxy(match: re.Match[bytes]) -> bytes:
        name = match[1]
        neutral_name = b"Meshlink" + name[len(b"Frida"):]
        aliases = b"typedef " + name + b" " + neutral_name + b";\n"
        aliases += b"typedef " + name + b"Class " + neutral_name + b"Class;\n"
        return aliases + match[0].replace(name, neutral_name, 1)

    source = DBUS_PROXY.sub(rename_dbus_proxy, source)

    def rename_values(match: re.Match[bytes]) -> bytes:
        values = ENUM_VALUE_NAME.sub(rb'"MESHLINK_\1"', match[2])
        return match[1] + values + match[3]

    return ENUM_VALUES.sub(rename_values, source)


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
        updated = neutralize_source_locations(
            neutralize_diagnostics(neutralize_runtime_types(neutralize_task_names(source)))
        )
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

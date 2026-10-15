import unittest
from pathlib import Path
from unittest.mock import patch

from releng.deps import (
    Bundle,
    SourceState,
    compute_bundle_parameters,
    ensure_toolchain,
    load_dependency_parameters,
)
from releng.machine_spec import MachineSpec


class SdkBundleUrlsTest(unittest.TestCase):
    def test_fork_sdk_urls_keep_windows_crt_variants_separate(self):
        for machine in (
            "linux-x86_64",
            "android-arm64",
            "windows-x86_64-md",
            "windows-x86_64-mt",
        ):
            with self.subTest(machine=machine):
                filename = f"sdk-{machine}.tar.xz"
                url, actual_filename = compute_bundle_parameters(
                    Bundle.SDK, MachineSpec.parse(machine), "20261015-meshlink"
                )
                self.assertEqual(actual_filename, filename)
                self.assertEqual(
                    url,
                    f"https://github.com/360NENZ/frida/releases/download/"
                    f"sdk-20261015-meshlink/{filename}",
                )

    def test_upstream_toolchain_version_remains_available(self):
        params = load_dependency_parameters()
        self.assertEqual(params.deps_version, "20261015-meshlink")
        self.assertEqual(params.toolchain_version, "20261004")

        machine = MachineSpec.parse("windows-x86_64-mt")
        url, filename = compute_bundle_parameters(
            Bundle.TOOLCHAIN, machine, params.toolchain_version
        )
        self.assertEqual(filename, "toolchain-windows-x86.tar.xz")
        self.assertEqual(
            url, "https://build.frida.re/deps/20261004/toolchain-windows-x86.tar.xz"
        )

        with patch("releng.deps.sync", return_value=SourceState.PRISTINE) as sync:
            ensure_toolchain(machine, Path("deps"))
        self.assertEqual(sync.call_args.args[3], "20261004")


if __name__ == "__main__":
    unittest.main()

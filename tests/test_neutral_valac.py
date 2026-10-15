import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from releng.neutral_valac import (
    neutralize_directory,
    neutralize_runtime_types,
    neutralize_task_names,
    output_directory,
)


class NeutralValacTest(unittest.TestCase):
    def test_rewrites_only_async_task_names(self):
        source = (
            b'g_task_set_name (_data_->_async_result, "Frida.Gadget.attach");\n'
            b'g_task_set_name (_data_->_async_result, "Other.Gadget.attach");\n'
            b'const char * public_name = "Frida.Gadget.attach";\n'
        )
        expected = source.replace(
            b'g_task_set_name (_data_->_async_result, "Frida.',
            b'g_task_set_name (_data_->_async_result, "Meshlink.',
        )
        self.assertEqual(neutralize_task_names(source), expected)

    def test_accepts_both_directory_forms(self):
        self.assertEqual(output_directory(["-C", "--directory", "out"]), Path("out"))
        self.assertEqual(output_directory(["-C", "--directory=out"]), Path("out"))
        self.assertIsNone(output_directory(["--version"]))

    def test_rewrites_type_registration_and_enum_metadata_only(self):
        source = (
            b'g_type_register_static (G_TYPE_OBJECT, "FridaScriptOptions", &info, 0);\n'
            b'g_type_register_fundamental (g_type_fundamental_next (), "FridaAcquiredRegion", &info, &fundamental, 0);\n'
            b'g_enum_register_static ("FridaRealm", values);\n'
            b'static const GEnumValue values[] = {{FRIDA_REALM_NATIVE, '
            b'"FRIDA_REALM_NATIVE", "native"}, {0, NULL, NULL}};\n'
            b'G_DEFINE_TYPE_EXTENDED (FridaAuthenticationServiceProxy, '
            b'frida_authentication_service_proxy, G_TYPE_DBUS_PROXY, 0, )\n'
            b'G_DEFINE_TYPE_EXTENDED (FridaLinuxRemoteHelperProxy, '
            b'frida_linux_remote_helper_proxy, G_TYPE_DBUS_PROXY, 0, )\n'
            b'G_DEFINE_TYPE_EXTENDED (FridaOtherObject, frida_other_object, G_TYPE_OBJECT, 0, )\n'
            b'g_quark_from_static_string ("frida-fruity-plist-error-quark");\n'
            b'g_dbus_error_register_error_domain ("frida-error-quark", &quark, entries, size);\n'
            b'const char * identifier = "FridaRealm";\n'
            b'const char * env = "FRIDA_TEST_OPTION";\n'
        )
        expected = source.replace(
            b'g_type_register_static (G_TYPE_OBJECT, "FridaScriptOptions"',
            b'g_type_register_static (G_TYPE_OBJECT, "MeshlinkScriptOptions"',
        ).replace(
            b'g_type_register_fundamental (g_type_fundamental_next (), "FridaAcquiredRegion"',
            b'g_type_register_fundamental (g_type_fundamental_next (), "MeshlinkAcquiredRegion"',
        ).replace(
            b'g_enum_register_static ("FridaRealm"',
            b'g_enum_register_static ("MeshlinkRealm"',
        ).replace(
            b'"FRIDA_REALM_NATIVE", "native"',
            b'"MESHLINK_REALM_NATIVE", "native"',
        ).replace(
            b'G_DEFINE_TYPE_EXTENDED (FridaAuthenticationServiceProxy, ',
            b'typedef FridaAuthenticationServiceProxy MeshlinkAuthenticationServiceProxy;\n'
            b'typedef FridaAuthenticationServiceProxyClass MeshlinkAuthenticationServiceProxyClass;\n'
            b'G_DEFINE_TYPE_EXTENDED (MeshlinkAuthenticationServiceProxy, ',
        ).replace(
            b'G_DEFINE_TYPE_EXTENDED (FridaLinuxRemoteHelperProxy, ',
            b'typedef FridaLinuxRemoteHelperProxy MeshlinkLinuxRemoteHelperProxy;\n'
            b'typedef FridaLinuxRemoteHelperProxyClass MeshlinkLinuxRemoteHelperProxyClass;\n'
            b'G_DEFINE_TYPE_EXTENDED (MeshlinkLinuxRemoteHelperProxy, ',
        ).replace(
            b'g_quark_from_static_string ("frida-fruity-plist-error-quark"',
            b'g_quark_from_static_string ("meshlink-fruity-plist-error-quark"',
        ).replace(
            b'g_dbus_error_register_error_domain ("frida-error-quark"',
            b'g_dbus_error_register_error_domain ("meshlink-error-quark"',
        )
        self.assertEqual(neutralize_runtime_types(source), expected)

    def test_rewrites_nested_generated_source(self):
        with TemporaryDirectory() as temp:
            target = Path(temp) / "fruity" / "injector.c"
            target.parent.mkdir()
            target.write_bytes(b'g_task_set_name (task, "Frida.Fruity.Injector.run");\n')
            neutralize_directory(Path(temp))
            self.assertEqual(
                target.read_bytes(),
                b'g_task_set_name (task, "Meshlink.Fruity.Injector.run");\n',
            )


if __name__ == "__main__":
    unittest.main()

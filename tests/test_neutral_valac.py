import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from releng.neutral_valac import neutralize_directory, neutralize_task_names, output_directory


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

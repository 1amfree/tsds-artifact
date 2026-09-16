import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent
COMPAT = ROOT / "satc_python3_compat.py"


class SaTCPython3CompatibilityTest(unittest.TestCase):
    def test_legacy_names_are_available_without_rewriting_target_source(self):
        with tempfile.TemporaryDirectory() as directory:
            script = Path(directory) / "legacy_satc_fixture.py"
            script.write_text(
                "import sys\n"
                "from urlparse import urljoin, urlparse\n"
                "assert urlparse(urljoin('http://a/', 'b')).path == '/b'\n"
                "reload(sys)\n"
                "sys.setdefaultencoding('utf8')\n"
                "print('compat-ok')\n",
                encoding="utf-8",
            )
            completed = subprocess.run(
                [sys.executable, str(COMPAT), "--script", str(script), "--"],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertIn("compat-ok", completed.stdout)


if __name__ == "__main__":
    unittest.main()

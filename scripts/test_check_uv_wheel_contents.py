import unittest
from contextlib import redirect_stderr
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory
from zipfile import ZipFile

from check_uv_wheel_contents import check_uv_wheel, uv_build_expected, uv_expected


class CheckWheelContentsTests(unittest.TestCase):
    def test_release_versions(self):
        for version in ("0.13.5", "0.13.5+codeartifact.1", "0.13.5rc1+codeartifact.1"):
            for package, expected in (
                ("uv", uv_expected),
                ("uv_build", uv_build_expected),
            ):
                with self.subTest(version=version, package=package):
                    with TemporaryDirectory() as directory:
                        wheel = (
                            Path(directory) / f"{package}-{version}-py3-none-any.whl"
                        )
                        with ZipFile(wheel, "w") as archive:
                            for entry in expected:
                                archive.writestr(entry.replace("VERSION", version), "")
                        check_uv_wheel(wheel)

    def test_unexpected_contents(self):
        with TemporaryDirectory() as directory:
            version = "0.13.5+codeartifact.1"
            wheel = Path(directory) / f"uv-{version}-py3-none-any.whl"
            with ZipFile(wheel, "w") as archive:
                for entry in uv_expected:
                    archive.writestr(entry.replace("VERSION", version), "")
                archive.writestr("unexpected.txt", "")
            with redirect_stderr(StringIO()), self.assertRaises(SystemExit):
                check_uv_wheel(wheel)


if __name__ == "__main__":
    unittest.main()

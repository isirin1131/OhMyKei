"""Run inside Colima: load only UHID from the matching Ubuntu kernel package."""
import pathlib
import hashlib
import subprocess
import tarfile

if pathlib.Path("/dev/uhid").exists():
    print("UHID already available")
    raise SystemExit(0)

release = subprocess.check_output(["uname", "-r"], text=True).strip()
deps = pathlib.Path(__file__).resolve().parents[2] / "build/virtual-hid/deps"
deps.mkdir(parents=True, exist_ok=True)
package = "linux-modules-extra-" + release
packages = list(deps.glob(package + "_*.deb"))
if not packages:
    subprocess.run(["apt-get", "download", package], cwd=deps, check=True)
    packages = list(deps.glob(package + "_*.deb"))
if len(packages) != 1:
    raise SystemExit("Expected exactly one matching kernel package")

module = None
process = subprocess.Popen(["dpkg-deb", "--fsys-tarfile", str(packages[0])], stdout=subprocess.PIPE)
with tarfile.open(fileobj=process.stdout, mode="r|") as archive:
    for member in archive:
        name = member.name.removeprefix("./")
        expected = f"lib/modules/{release}/kernel/drivers/hid/uhid.ko"
        if member.isfile() and name in (expected, expected + ".zst", expected + ".xz"):
            module = deps / pathlib.Path(name).name
            # New dependency artifact; never overwrite a linked file.
            if module.is_symlink():
                raise SystemExit("Refusing a linked module artifact")
            content = archive.extractfile(member).read()
            if module.exists():
                if hashlib.sha256(module.read_bytes()).digest() != hashlib.sha256(content).digest():
                    raise SystemExit("Existing UHID module does not match the package")
            else:
                with module.open("xb") as output:
                    output.write(content)
process.stdout.close()
if process.wait() != 0 or module is None:
    raise SystemExit("UHID module extraction failed")
subprocess.run(["sudo", "-n", "insmod", str(module)], check=True)
subprocess.run(["sudo", "-n", "udevadm", "settle", "--timeout=10"], check=True)
if not pathlib.Path("/dev/uhid").is_char_device():
    raise SystemExit("UHID loaded but /dev/uhid is absent")
print("UHID loaded for", release)

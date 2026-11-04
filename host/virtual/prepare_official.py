"""Copy the local official app's runtime sources verbatim for a Linux launch.

No tests or transport implementations are changed. Platform-native dependencies
are installed separately by official.Dockerfile, using the shipped versions.
"""
import hashlib
import json
import pathlib
import struct

ROOT = pathlib.Path(__file__).resolve().parents[2]
SOURCE = ROOT / "tools/fido-conformance/app.asar"
OUTPUT = ROOT / "build/virtual-hid/official/app"
TOP_FILES = {"main.js", "preload.js", "webapp.js", "package.json", "icon.png", "icon.ico",
             "END USER LICENSE AGREEMENT FOR FIDO ALLIANCE FUNCTIONAL CERTIFICATION TEST TOOLS.pdf"}
TOP_DIRS = {"app", "dependencies", "modules"}


def main():
    hashes = {}
    OUTPUT.mkdir(parents=True, exist_ok=True)
    with SOURCE.open("rb") as archive:
        _, header_size, _, json_size = struct.unpack("<4I", archive.read(16))
        header = json.loads(archive.read(json_size))
        def copy_tree(files, prefix=pathlib.PurePosixPath()):
            for name, entry in files.items():
                if prefix == pathlib.PurePosixPath() and name not in TOP_FILES | TOP_DIRS:
                    continue
                path = prefix / name
                if path.is_absolute() or ".." in path.parts or "link" in entry:
                    raise RuntimeError("Unsupported archive path")
                target = OUTPUT / str(path)
                if not target.resolve().is_relative_to(OUTPUT.resolve()):
                    raise RuntimeError("Output path leaves the app directory")
                if "files" in entry:
                    target.mkdir(exist_ok=True)
                    copy_tree(entry["files"], path)
                else:
                    archive.seek(8 + header_size + int(entry["offset"]))
                    data = archive.read(entry["size"])
                    if target.exists():
                        if target.read_bytes() != data:
                            raise RuntimeError("Existing copy differs from official source: " + str(path))
                    else:
                        with target.open("xb") as output:
                            output.write(data)
                    hashes[str(path)] = hashlib.sha256(data).hexdigest()
        copy_tree(header["files"])
    (OUTPUT.parent / "source-hashes.json").write_text(json.dumps(hashes, indent=2) + "\n")
    print("Prepared", len(hashes), "unchanged official runtime files")


if __name__ == "__main__":
    main()

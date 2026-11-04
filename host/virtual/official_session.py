"""Run the unchanged official Electron app against a fresh virtual device."""
import os
import argparse
import pathlib
import signal
import subprocess
import tempfile
import threading
import time
import urllib.request
import json
import hashlib

from service import Device, make_server

ROOT = pathlib.Path(__file__).resolve().parents[2]
BASE = ROOT / "build/virtual-hid/official"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--suite", choices=["full", "smoke"], default="full")
    parser.add_argument("--group", action="append", default=[])
    parser.add_argument("--grep", default="")
    parser.add_argument("--timeout", type=int)
    args = parser.parse_args()
    timeout = args.timeout if args.timeout is not None else (180 if args.suite == "smoke" else 1800)
    if timeout <= 0 or (args.suite == "smoke" and args.group):
        parser.error("Use a positive timeout and --suite full for group selection")
    modules = BASE / "app/node_modules"
    target = pathlib.Path("/opt/fido/node_modules")
    if modules.is_symlink():
        if modules.readlink() != target:
            raise RuntimeError("Unexpected official dependency link")
    elif not modules.exists() and target.is_dir() and not target.is_symlink():
        modules.symlink_to(target, target_is_directory=True)
    else:
        raise RuntimeError("Official dependency location is not the prepared runtime")
    session = pathlib.Path(tempfile.mkdtemp(prefix="session-", dir=BASE))
    report = session / "result.json"
    environment = {"commit": os.environ.get("OMK_TEST_COMMIT"),
                   "dirty": os.environ.get("OMK_TEST_DIRTY"),
                   "image": os.environ.get("OMK_TEST_IMAGE_ID"), "sha256": {}}
    for name in ("build/virtual-hid/linux/host/omk_virtual", "host/virtual/metadata.json",
                 "host/virtual/official_runner.mjs", "host/virtual/official-package-lock.json",
                 "build/virtual-hid/official/source-hashes.json"):
        environment["sha256"][name] = hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
    environment_file = session / "environment.json"
    environment_file.write_text(json.dumps(environment, indent=2) + "\n")
    options = {"suite": args.suite, "groups": args.group, "grep": args.grep,
               "timeout": timeout, "environment": str(environment_file)}
    device = Device(ROOT / "build/virtual-hid/linux/host/omk_virtual", session / "device.flash")
    device.auto_ms = None  # Only the official automation callback grants UP.
    server = make_server(device, ("127.0.0.1", 3000), session / "results.json")
    children = []
    def stop(signum, frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    with (session / "runtime.log").open("w") as log:
        try:
            threading.Thread(target=server.serve_forever, daemon=True).start()
            device.powercycle()
            children.append(subprocess.Popen(
                ["Xvfb", ":99", "-screen", "0", "1280x800x24", "-nolisten", "tcp"],
                stdout=subprocess.DEVNULL, stderr=log,
            ))
            deadline = time.monotonic() + 5
            while not pathlib.Path("/tmp/.X11-unix/X99").exists():
                if time.monotonic() >= deadline:
                    raise RuntimeError("Xvfb did not start")
                time.sleep(0.05)
            env = dict(os.environ, DISPLAY=":99", ELECTRON_IS_DEV="0")
            env.pop("ELECTRON_RUN_AS_NODE", None)
            electron = subprocess.Popen([
                "env", "-u", "ELECTRON_RUN_AS_NODE",
                "/opt/fido/node_modules/electron/dist/electron",
                "--no-sandbox", "--disable-gpu", "--remote-debugging-port=9222",
                "--user-data-dir=" + str(session / "profile"),
                str(BASE / "app"), "--prompt-has-display=false", "--prompt-u2f-compat=false",
            ], env=env, stdout=subprocess.DEVNULL, stderr=log)
            children.append(electron)
            print("Official session:", session.relative_to(ROOT), flush=True)
            deadline = time.monotonic() + 20
            while time.monotonic() < deadline:
                try:
                    with urllib.request.urlopen("http://127.0.0.1:9222/json/list", timeout=1) as r:
                        if any(p.get("type") == "page" for p in json.load(r)):
                            break
                except OSError:
                    pass
                time.sleep(0.1)
            else:
                raise RuntimeError("Official app did not create a CDP page")
            runner = subprocess.Popen([
                "node", "host/virtual/official_runner.mjs", str(report), json.dumps(options)
            ])
            children.append(runner)
            code = runner.wait(timeout=timeout + 60)
            print("Official report:", report.relative_to(ROOT), flush=True)
            raise SystemExit(code)
        except KeyboardInterrupt:
            failure = "interrupted"
            code = 130
        except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
            failure = type(error).__name__
            code = 2
        finally:
            for child in reversed(children):
                if child.poll() is None:
                    child.terminate()
                    try:
                        child.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        child.kill()
                        child.wait(timeout=3)
            server.shutdown()
            server.server_close()
            device.stop()
    # Reached only on setup failure, interruption or the supervisor deadline.
    partial = json.loads(report.read_text()) if report.exists() else {"environment": environment}
    partial.update(done=False, infrastructureError={"phase": "supervisor", "error": failure},
                   assessment={"outcome": "incomplete", "exitCode": code})
    report.write_text(json.dumps(partial, indent=2) + "\n")
    print("Official report:", report.relative_to(ROOT), flush=True)
    raise SystemExit(code)


if __name__ == "__main__":
    main()

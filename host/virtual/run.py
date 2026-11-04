"""From macOS: python3 host/virtual/run.py test|serve|official|build|stop."""
import argparse
import json
import pathlib
import subprocess
import time

ROOT = pathlib.Path(__file__).resolve().parents[2]
DOCKER = ["docker", "--host", "unix://" + str(pathlib.Path.home() / ".colima/default/docker.sock")]
CONTAINER = "ohmykei-virtual"
IMAGE = "ohmykei-virtual:1"
ACTIVE_CONTAINER = CONTAINER


def run(*args, **kwargs):
    return subprocess.run(list(args), check=True, **kwargs)


def main():
    global ACTIVE_CONTAINER
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["test", "serve", "official", "build", "stop"])
    args = parser.parse_args()
    if args.action == "stop":
        for name in (CONTAINER, "ohmykei-conformance"):
            found = subprocess.run(DOCKER + ["container", "inspect", name], capture_output=True)
            if found.returncode == 0:
                run(*DOCKER, "stop", name)
        return
    run("colima", "ssh", "--", "python3", str(ROOT / "host/virtual/load_uhid.py"))
    run(*DOCKER, "build", "-t", IMAGE, str(ROOT / "host/virtual"))
    image = IMAGE
    if args.action == "official":
        ACTIVE_CONTAINER = "ohmykei-conformance"
        image = "ohmykei-conformance:1"
        run("python3", str(ROOT / "host/virtual/prepare_official.py"))
        run(*DOCKER, "build", "-f", str(ROOT / "host/virtual/official.Dockerfile"),
            "-t", image, str(ROOT / "host/virtual"))
    state = subprocess.run(DOCKER + ["container", "inspect", ACTIVE_CONTAINER],
                           capture_output=True, text=True)
    if state.returncode == 0:
        current = json.loads(state.stdout)[0]
        image_id = subprocess.check_output(DOCKER + ["image", "inspect", image, "--format", "{{.Id}}"],
                                           text=True).strip()
        if current["Image"] != image_id:
            if current["State"]["Running"]:
                run(*DOCKER, "stop", ACTIVE_CONTAINER)
            # Preserve the old container instead of deleting it.
            run(*DOCKER, "rename", ACTIVE_CONTAINER, ACTIVE_CONTAINER + "-retired-" + str(time.time_ns()))
            state.returncode = 1
    if state.returncode:
        major = subprocess.check_output([
            "colima", "ssh", "--", "sh", "-c", "awk '$2 == \"hidraw\" {print $1}' /proc/devices"
        ], text=True).strip()
        if not major.isdecimal():
            raise SystemExit("No hidraw major number found")
        ports = [] if args.action == "official" else ["-p", "127.0.0.1:3000:3000"]
        run(*DOCKER, "run", "-d", "-i", "--name", ACTIVE_CONTAINER,
            "--device=/dev/uhid", "--device-cgroup-rule=c " + major + ":* rwm",
            "--mount", "type=bind,src=/dev,dst=/dev",
            "--mount", f"type=bind,src={ROOT},dst=/workspace",
            *ports, image, "sleep", "infinity")
    elif not json.loads(state.stdout)[0]["State"]["Running"]:
        run(*DOCKER, "start", ACTIVE_CONTAINER)
    execute = DOCKER + ["exec", "-w", "/workspace", ACTIVE_CONTAINER]
    run(*execute, "cmake", "-S", ".", "-B", "build/virtual-hid/linux", "-G", "Ninja",
        "-DOMK_HOST_BUILD=ON", "-DCMAKE_BUILD_TYPE=Debug")
    run(*execute, "cmake", "--build", "build/virtual-hid/linux", "--parallel", "2")
    if args.action == "test":
        run(*execute, "ctest", "--test-dir", "build/virtual-hid/linux", "-E", "^host\\.",
            "--output-on-failure")
        run(*execute, "timeout", "120", "python", "host/virtual/test_e2e.py")
    elif args.action == "serve":
        # Dedicated persistent test store, separate from every regression run.
        run(*execute, "python", "host/virtual/service.py", "--listen", "0.0.0.0",
            "--flash", "build/virtual-hid/device.flash")
    elif args.action == "official":
        run(*execute, "python", "host/virtual/official_session.py", "--smoke")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        # docker exec's client does not reliably forward Ctrl-C into the guest.
        # This dedicated container owns all of our virtual device processes.
        subprocess.run(DOCKER + ["stop", "--time", "3", ACTIVE_CONTAINER], check=False)
        raise SystemExit(130)

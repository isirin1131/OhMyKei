"""Virtual device supervisor and FIDO's documented automation HTTP endpoints."""
import argparse
import hashlib
import json
import pathlib
import queue
import signal
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Device:
    def __init__(self, binary, flash):
        self.binary = str(binary)
        self.flash = str(flash)
        self.serial = "OMK-VIRTUAL-" + hashlib.sha256(
            str(pathlib.Path(flash).resolve()).encode()
        ).hexdigest()[:16]
        self.process = None
        self.events = queue.Queue()
        self.lock = threading.Lock()
        self.auto_ms = 250
        self.generation = 0

    def _read_events(self, process, events):
        for line in process.stdout:
            events.put(line.strip())
        events.put("EXIT")

    def _wait(self, expected, timeout=10):
        deadline = time.monotonic() + timeout
        while True:
            event = self.events.get(timeout=max(0, deadline - time.monotonic()))
            if event == expected:
                return
            if event == "EXIT":
                raise RuntimeError("virtual device exited; inspect its stderr")
            if event == "NOT_WAITING":
                raise RuntimeError("no operation is waiting for user presence")

    def _command(self, command):
        if self.process is None or self.process.poll() is not None:
            raise RuntimeError("virtual device is not running")
        self.process.stdin.write(command + "\n")
        self.process.stdin.flush()

    def _stop(self):
        if self.process is not None:
            self.process.terminate()
            try:
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=3)
            self.process.stdin.close()
            self.reader.join(timeout=1)
            self.process.stdout.close()
            self.process = None

    def powercycle(self):
        with self.lock:
            self._stop()
            self.events = queue.Queue()
            self.process = subprocess.Popen(
                [self.binary, self.flash, self.serial], stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, text=True, bufsize=1,
            )
            self.reader = threading.Thread(
                target=self._read_events, args=(self.process, self.events), daemon=True
            )
            self.reader.start()
            self._wait("READY")
            self._set_mode(self.auto_ms)
            # Wait for this device to be present in sysfs before acknowledging.
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                if len(self.paths()) == 1:
                    self.generation += 1
                    return
                time.sleep(0.02)
            raise RuntimeError("UHID did not enumerate")

    def paths(self):
        result = []
        if self.process is None:
            return result
        for node in pathlib.Path("/sys/class/hidraw").glob("hidraw*/device/uevent"):
            try:
                text = node.read_text()
            except FileNotFoundError:
                continue  # A device can disappear during a power cycle.
            if f"HID_UNIQ={self.serial}\n" in text:
                path = pathlib.Path("/dev") / node.parent.parent.name
                if path.exists():
                    result.append(str(path))
        return result

    def _set_mode(self, delay):
        self._command("manual" if delay is None else f"auto {delay}")
        self._wait("MODE")
        self.auto_ms = delay

    def mode(self, delay):
        if delay is not None and (type(delay) is not int or not 10 <= delay <= 10000):
            raise ValueError("auto_touch_ms must be null or an integer from 10 to 10000")
        with self.lock:
            self._set_mode(delay)

    def touch(self):
        with self.lock:
            # Ignore acknowledgements from earlier automatic touches.
            while not self.events.empty():
                self.events.get_nowait()
            self._command("touch")
            self._wait("TOUCHED")

    def stop(self):
        with self.lock:
            self._stop()


def make_server(device, address, results):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass  # No request bodies, credentials, tokens or PINs in logs.

        def reply(self, status, obj):
            payload = json.dumps(obj).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def do_GET(self):
            if self.path != "/health":
                return self.reply(404, {"error": "unknown endpoint"})
            self.reply(200, {"generation": device.generation, "devices": device.paths()})

        def do_POST(self):
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if not 0 <= length <= 1024 * 1024:
                    return self.reply(413, {"error": "request too large"})
                data = self.rfile.read(length)
                if self.path in ("/conformance/powercycle", "/control/powercycle"):
                    device.powercycle()
                elif self.path in ("/conformance/userpresence", "/control/touch"):
                    device.touch()
                elif self.path == "/control/mode":
                    device.mode(json.loads(data)["auto_touch_ms"])
                elif self.path == "/conformance/results":
                    result = json.loads(data)
                    # Persist only aggregate counts, never full test payloads.
                    summary = {k: result[k] for k in (
                        "allTestsSelected", "passedTestsCount", "failedTestsCount"
                    ) if k in result}
                    pathlib.Path(results).write_text(json.dumps(summary, indent=2) + "\n")
                else:
                    return self.reply(404, {"error": "unknown endpoint"})
                self.reply(200, {"ok": True, "generation": device.generation})
            except (ValueError, KeyError, TypeError):
                self.reply(400, {"error": "invalid request"})
            except (RuntimeError, OSError, queue.Empty):
                self.reply(503, {"error": "device operation did not complete"})

    server = ThreadingHTTPServer(address, Handler)
    server.daemon_threads = True
    return server


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="build/virtual-hid/linux/host/omk_virtual")
    parser.add_argument("--flash", required=True)
    parser.add_argument("--listen", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=3000)
    parser.add_argument("--manual", action="store_true")
    args = parser.parse_args()
    device = Device(args.binary, args.flash)
    if args.manual:
        device.auto_ms = None
    server = make_server(device, (args.listen, args.port), args.flash + ".results.json")
    def shutdown(signum, frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, shutdown)
    try:
        device.powercycle()
        print("Virtual FIDO ready; automation HTTP port", server.server_port, flush=True)
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        device.stop()


if __name__ == "__main__":
    main()

"""
Simulated legacy edge device - an Arduino-class sensor node.

WHAT THIS IS
    A stand-in for real field hardware: a microcontroller with a temperature
    and humidity sensor, a few kilobytes of RAM, no operating system, and
    firmware written years ago by someone who has left.

WHY WE SIMULATE IT
    The project needs a component that genuinely cannot be upgraded, because
    that constraint is what makes the post-quantum migration interesting. A
    simulator lets us be precise about the limits (see MAX_FRAME_BYTES in
    protocol.py) instead of hand-waving about them.

WHAT IT MODELS FAITHFULLY
    * One hardcoded pre-shared key, no key establishment (see protocol.py).
    * A tiny receive buffer, enforced when building frames.
    * A retry-forever reconnect loop: field devices have nobody to report an
      error to, so they simply keep trying.
    * A monotonic sequence counter the gateway uses for replay detection.

WHAT IT DOES NOT MODEL
    Power budget, radio behaviour, clock drift, or flash wear. None of those
    change the cryptographic argument, so they are out of scope - the project
    brief asks us to keep this simple.

Run:
    python -m legacy_device.device --device-id dev-001 --interval 2
"""

import argparse
import logging
import random
import socket
import time

from legacy_device.protocol import build_reading, encrypt_frame

log = logging.getLogger("legacy-device")

# How long to wait before reconnecting after the link drops. Real firmware
# uses a back-off; a fixed delay is enough here and keeps the logs readable
# during a demo.
RECONNECT_DELAY_S = 5.0

# Socket timeout for the initial connect. Without it a device pointed at a
# black-holed address would block forever instead of retrying.
CONNECT_TIMEOUT_S = 10.0


class SensorSimulator:
    """Produces plausible temperature and humidity readings.

    A random walk rather than independent random values, because real
    environmental sensors change gradually. That matters for the project: flat
    or wildly jumping data would make it impossible to tell, when looking at a
    dashboard, whether the pipeline is actually delivering fresh readings.

    Values are clamped to ranges the cloud service accepts, so the baseline
    system never produces data its own API would reject.
    """

    def __init__(self, temp_c: float = 21.0, humidity: float = 45.0) -> None:
        self.temp_c = temp_c
        self.humidity = humidity

    def read(self) -> tuple[float, float]:
        """Return one (temperature_c, humidity_percent) sample.

        Both sensors are read together and reported in a single frame. That is
        a deliberate choice for a battery-powered device: one frame per sample
        cycle costs half the radio time of two.

        `random` is fine here: it simulates sensor noise, not a secret. The
        "noqa: S311" marks below record that the static-analysis warning was
        reviewed. The frame IV in protocol.py does use os.urandom.
        """
        self.temp_c = round(
            min(35.0, max(5.0, self.temp_c + random.uniform(-0.3, 0.3))), 2  # noqa: S311
        )
        self.humidity = round(
            min(95.0, max(10.0, self.humidity + random.uniform(-0.8, 0.8))), 2  # noqa: S311
        )
        return self.temp_c, self.humidity


class LegacyDevice:
    """One simulated device: connects to a gateway and streams readings."""

    def __init__(self, device_id: str, host: str, port: int,
                 interval_s: float) -> None:
        self.device_id = device_id
        self.host = host
        self.port = port
        self.interval_s = interval_s
        self.sensor = SensorSimulator()

        # Sequence numbers start at 1 and only ever increase. The gateway
        # rejects anything that does not, which is the baseline system's only
        # replay protection. Note the weakness: this counter resets to 0 if the
        # device reboots, and the gateway will then drop every reading until it
        # climbs past the old high-water mark.
        self.seq = 0

        # monotonic() rather than time() so that a system clock adjustment
        # cannot make uptime go backwards.
        self.booted_at = time.monotonic()

    def _uptime_s(self) -> int:
        """Seconds since this device "powered on"."""
        return int(time.monotonic() - self.booted_at)

    def _send_forever(self, sock: socket.socket) -> None:
        """Send one reading per interval until the socket breaks.

        Returns normally only if the loop is interrupted; any socket failure
        propagates to run(), which handles reconnection. Keeping the retry
        logic in one place stops the two concerns from tangling.
        """
        while True:
            temp_c, humidity = self.sensor.read()
            self.seq += 1

            record = build_reading(
                self.device_id, self.seq, temp_c, humidity, self._uptime_s()
            )

            # sendall rather than send: a partial write would corrupt the frame
            # boundary, and the gateway reads by newline.
            sock.sendall(encrypt_frame(record))

            log.info("sent seq=%d temp=%.2f humidity=%.2f",
                     self.seq, temp_c, humidity)

            time.sleep(self.interval_s)

    def run(self) -> None:
        """Connect to the gateway and stream readings, retrying forever.

        Retrying forever is correct for this component, not lazy: a sensor in a
        wall has no operator and no alternative. It is also why the gateway
        must tolerate connections appearing and vanishing at any time.
        """
        log.info("device %s starting, target %s:%d",
                 self.device_id, self.host, self.port)

        while True:
            try:
                with socket.create_connection(
                    (self.host, self.port), timeout=CONNECT_TIMEOUT_S
                ) as sock:
                    log.info("connected to gateway")
                    self._send_forever(sock)
            except OSError as exc:
                # OSError covers the whole family: connection refused, reset,
                # timed out, host unreachable, and network down. All of them
                # mean the same thing to a field device - wait and retry.
                log.warning("link down (%s), retrying in %.0fs",
                            exc, RECONNECT_DELAY_S)
                time.sleep(RECONNECT_DELAY_S)


def main() -> None:
    parser = argparse.ArgumentParser(description="Simulated legacy device")
    parser.add_argument("--device-id", default="dev-001",
                        help="identity sent in every frame")
    parser.add_argument("--host", default="127.0.0.1",
                        help="gateway address")
    parser.add_argument("--port", type=int, default=9000,
                        help="gateway TCP port")
    parser.add_argument("--interval", type=float, default=2.0,
                        help="seconds between readings")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )

    try:
        LegacyDevice(args.device_id, args.host, args.port, args.interval).run()
    except KeyboardInterrupt:
        # Ctrl+C is how we stop a simulated device, so exit quietly rather
        # than printing a traceback.
        log.info("device stopped")


if __name__ == "__main__":
    main()

"""
Metrics in the Prometheus text format, without the prometheus_client library.

A /metrics endpoint returns plain text like:

    # HELP cloud_readings_ingested_total Readings stored, by delivery path.
    # TYPE cloud_readings_ingested_total counter
    cloud_readings_ingested_total{channel="mlkem"} 42

Prometheus (or anything else) can scrape it, and a person can read it with
curl. The format is simple enough that writing it directly is clearer than
adding a dependency to both services: about 100 lines, all tested in
tests/test_observability.py.

Counters live in memory, so they restart from zero when the service restarts.
Prometheus handles that by design (rate() detects counter resets).
"""

import threading
from collections.abc import Iterable
from dataclasses import dataclass, field

Labels = tuple[tuple[str, str], ...]


@dataclass
class Family:
    """One metric name with its type, help text and samples."""

    name: str
    kind: str                      # "counter", "gauge" or "summary"
    help: str
    samples: list[tuple[str, Labels, float]] = field(default_factory=list)


def _escape(value: str) -> str:
    """Escape a label value as the text format requires."""
    return (value.replace("\\", "\\\\").replace("\n", "\\n")
            .replace('"', '\\"'))


def _format_value(value: float) -> str:
    return str(int(value)) if float(value).is_integer() else repr(float(value))


def render(families: Iterable[Family]) -> str:
    """Render metric families as Prometheus text exposition format 0.0.4."""
    lines = []
    for family in families:
        lines.append(f"# HELP {family.name} {family.help}")
        lines.append(f"# TYPE {family.name} {family.kind}")
        for sample_name, labels, value in family.samples:
            label_text = ",".join(f'{k}="{_escape(v)}"' for k, v in labels)
            label_part = f"{{{label_text}}}" if label_text else ""
            lines.append(f"{sample_name}{label_part} {_format_value(value)}")
    return "\n".join(lines) + "\n"


def gauge(name: str, help_text: str, value: float, **labels: str) -> Family:
    """A single-sample gauge, for values computed at scrape time."""
    return Family(name, "gauge", help_text,
                  [(name, tuple(sorted(labels.items())), value)])


class Registry:
    """Thread-safe counters and summaries that a service updates as it runs.

    Metrics must be declared before use, so a typo in a metric name fails
    loudly in tests instead of silently creating a new series.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._declared: dict[str, tuple[str, str]] = {}
        self._values: dict[tuple[str, Labels], float] = {}

    def counter(self, name: str, help_text: str) -> None:
        self._declared[name] = ("counter", help_text)

    def summary(self, name: str, help_text: str) -> None:
        """A summary without quantiles: _sum and _count, enough for an
        average (rate of sum divided by rate of count)."""
        self._declared[name] = ("summary", help_text)

    def inc(self, name: str, amount: float = 1, **labels: str) -> None:
        self._require(name, "counter")
        key = (name, tuple(sorted(labels.items())))
        with self._lock:
            self._values[key] = self._values.get(key, 0) + amount

    def observe(self, name: str, value: float) -> None:
        self._require(name, "summary")
        with self._lock:
            for suffix, amount in (("_sum", value), ("_count", 1)):
                key = (name + suffix, ())
                self._values[key] = self._values.get(key, 0) + amount

    def value(self, name: str, **labels: str) -> float:
        """Current value of one series, 0 if never incremented."""
        with self._lock:
            return self._values.get((name, tuple(sorted(labels.items()))), 0)

    def families(self) -> list[Family]:
        with self._lock:
            values = dict(self._values)
        result = []
        for name, (kind, help_text) in self._declared.items():
            family = Family(name, kind, help_text)
            for (sample, labels), value in sorted(values.items()):
                if sample == name or (kind == "summary"
                                      and sample in (name + "_sum",
                                                     name + "_count")):
                    family.samples.append((sample, labels, value))
            if kind == "summary" and not family.samples:
                family.samples = [(name + "_sum", (), 0),
                                  (name + "_count", (), 0)]
            result.append(family)
        return result

    def _require(self, name: str, kind: str) -> None:
        declared = self._declared.get(name)
        if declared is None or declared[0] != kind:
            raise KeyError(f"metric {name!r} is not declared as a {kind}")

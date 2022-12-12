#!/usr/bin/python

from __future__ import unicode_literals

import math
import re

from ..metrics_core import Metric, METRIC_LABEL_NAME_RE
from ..samples import Exemplar, Sample, Timestamp
from ..utils import floatToGoString

try:
    import StringIO
except ImportError:
    # Python 3
    import io as StringIO


def text_string_to_metric_families(text):
    """Parse Openmetrics text format from a unicode string.

    See text_fd_to_metric_families.
    """
    for metric_family in text_fd_to_metric_families(StringIO.StringIO(text)):
        yield metric_family


_CANONICAL_NUMBERS = set([float("inf")])


def _isUncanonicalNumber(s):
    f = float(s)
    if f not in _CANONICAL_NUMBERS:
        return False  # Only the canonical numbers are required to be canonical.
    return s != floatToGoString(f)


ESCAPE_SEQUENCES = {
    "\\\\": "\\",
    "\\n": "\n",
    '\\"': '"',
}


def _replace_escape_sequence(match):
    return ESCAPE_SEQUENCES[match.group(0)]


ESCAPING_RE = re.compile(r'\\[\\n"]')


def _replace_escaping(s):
    return ESCAPING_RE.sub(_replace_escape_sequence, s)


def _unescape_help(text):
    result = []
    slash = False

    for char in text:
        if slash:
            if char == "\\":
                result.append("\\")
            elif char == '"':
                result.append('"')
            elif char == "n":
                result.append("\n")
            else:
                result.append("\\" + char)
            slash = False
        else:
            if char == "\\":
                slash = True
            else:
                result.append(char)

    if slash:
        result.append("\\")

    return "".join(result)


def _parse_value(value):
    value = "".join(value)
    if value != value.strip() or "_" in value:
        raise ValueError("Invalid value: {0!r}".format(value))
    try:
        return int(value)
    except ValueError:
        return float(value)


def _parse_timestamp(timestamp):
    timestamp = "".join(timestamp)
    if not timestamp:
        return None
    if timestamp != timestamp.strip() or "_" in timestamp:
        raise ValueError("Invalid timestamp: {0!r}".format(timestamp))
    try:
        # Simple int.
        return Timestamp(int(timestamp), 0)
    except ValueError:
        try:
            # aaaa.bbbb. Nanosecond resolution supported.
            parts = timestamp.split(".", 1)
            return Timestamp(int(parts[0]), int(parts[1][:9].ljust(9, "0")))
        except ValueError:
            # Float.
            ts = float(timestamp)
            if math.isnan(ts) or math.isinf(ts):
                raise ValueError("Invalid timestamp: {0!r}".format(timestamp))
            return ts


def _is_character_escaped(s, charpos):
    num_bslashes = 0
    while charpos > num_bslashes and s[charpos - 1 - num_bslashes] == "\\":
        num_bslashes += 1
    return num_bslashes % 2 == 1


def _parse_labels_with_state_machine(text):
    # The { has already been parsed.
    state = "startoflabelname"
    labelname = []
    labelvalue = []
    labels = {}
    labels_len = 0

    for char in text:
        if state == "startoflabelname":
            if char == "}":
                state = "endoflabels"
            else:
                state = "labelname"
                labelname.append(char)
        elif state == "labelname":
            if char == "=":
                state = "labelvaluequote"
            else:
                labelname.append(char)
        elif state == "labelvaluequote":
            if char == '"':
                state = "labelvalue"
            else:
                raise ValueError("Invalid line: " + text)
        elif state == "labelvalue":
            if char == "\\":
                state = "labelvalueslash"
            elif char == '"':
                ln = "".join(labelname)
                if not METRIC_LABEL_NAME_RE.match(ln):
                    raise ValueError("Invalid line, bad label name: " + text)
                if ln in labels:
                    raise ValueError("Invalid line, duplicate label name: " + text)
                labels[ln] = "".join(labelvalue)
                labelname = []
                labelvalue = []
                state = "endoflabelvalue"
            else:
                labelvalue.append(char)
        elif state == "endoflabelvalue":
            if char == ",":
                state = "labelname"
            elif char == "}":
                state = "endoflabels"
            else:
                raise ValueError("Invalid line: " + text)
        elif state == "labelvalueslash":
            state = "labelvalue"
            if char == "\\":
                labelvalue.append("\\")
            elif char == "n":
                labelvalue.append("\n")
            elif char == '"':
                labelvalue.append('"')
            else:
                labelvalue.append("\\" + char)
        elif state == "endoflabels":
            if char == " ":
                break
            else:
                raise ValueError("Invalid line: " + text)
        labels_len += 1
    return labels, labels_len


def _parse_labels(text):
    labels = {}

    # Raise error if we don't have valid labels
    if text and "=" not in text:
        raise ValueError

    # Copy original labels
    sub_labels = text
    try:
        # Process one label at a time
        while sub_labels:
            # The label name is before the equal
            value_start = sub_labels.index("=")
            label_name = sub_labels[:value_start]
            sub_labels = sub_labels[value_start + 1 :]

            # Check for missing quotes
            if not sub_labels or sub_labels[0] != '"':
                raise ValueError

            # The first quote is guaranteed to be after the equal
            value_substr = sub_labels[1:]

            # Check for extra commas
            if not label_name or label_name[0] == ",":
                raise ValueError
            if not value_substr or value_substr[-1] == ",":
                raise ValueError

            # Find the last unescaped quote
            i = 0
            while i < len(value_substr):
                i = value_substr.index('"', i)
                if not _is_character_escaped(value_substr[:i], i):
                    break
                i += 1

            # The label value is between the first and last quote
            quote_end = i + 1
            label_value = sub_labels[1:quote_end]
            # Replace escaping if needed
            if "\\" in label_value:
                label_value = _replace_escaping(label_value)
            if not METRIC_LABEL_NAME_RE.match(label_name):
                raise ValueError("invalid line, bad label name: " + text)
            if label_name in labels:
                raise ValueError("invalid line, duplicate label name: " + text)
            labels[label_name] = label_value

            # Remove the processed label from the sub-slice for next iteration
            sub_labels = sub_labels[quote_end + 1 :]
            if sub_labels.startswith(","):
                next_comma = 1
            else:
                next_comma = 0
            sub_labels = sub_labels[next_comma:]

            # Check for missing commas
            if sub_labels and next_comma == 0:
                raise ValueError

        return labels

    except ValueError:
        raise ValueError("Invalid labels: " + text)


def _parse_sample(text):
    separator = " # "
    # Detect the labels in the text
    label_start = text.find("{")
    if label_start == -1 or separator in text[:label_start]:
        # We don't have labels, but there could be an exemplar.
        name_end = text.index(" ")
        name = text[:name_end]
        # Parse the remaining text after the name
        remaining_text = text[name_end + 1 :]
        value, timestamp, exemplar = _parse_remaining_text(remaining_text)
        return Sample(name, {}, value, timestamp, exemplar)
    # The name is before the labels
    name = text[:label_start]
    if separator not in text:
        # Line doesn't contain an exemplar
        # We can use `rindex` to find `label_end`
        label_end = text.rindex("}")
        label = text[label_start + 1 : label_end]
        labels = _parse_labels(label)
    else:
        # Line potentially contains an exemplar
        # Fallback to parsing labels with a state machine
        labels, labels_len = _parse_labels_with_state_machine(text[label_start + 1 :])
        label_end = labels_len + len(name)
    # Parsing labels succeeded, continue parsing the remaining text
    remaining_text = text[label_end + 2 :]
    value, timestamp, exemplar = _parse_remaining_text(remaining_text)
    return Sample(name, labels, value, timestamp, exemplar)


def _parse_remaining_text(text):
    split_text = text.split(" ", 1)
    val = _parse_value(split_text[0])
    if len(split_text) == 1:
        # We don't have timestamp or exemplar
        return val, None, None

    timestamp = []
    exemplar_value = []
    exemplar_timestamp = []
    exemplar_labels = None

    state = "timestamp"
    text = split_text[1]

    it = iter(text)
    for char in it:
        if state == "timestamp":
            if char == "#" and not timestamp:
                state = "exemplarspace"
            elif char == " ":
                state = "exemplarhash"
            else:
                timestamp.append(char)
        elif state == "exemplarhash":
            if char == "#":
                state = "exemplarspace"
            else:
                raise ValueError("Invalid line: " + text)
        elif state == "exemplarspace":
            if char == " ":
                state = "exemplarstartoflabels"
            else:
                raise ValueError("Invalid line: " + text)
        elif state == "exemplarstartoflabels":
            if char == "{":
                label_start, label_end = text.index("{"), text.rindex("}")
                exemplar_labels = _parse_labels(text[label_start + 1 : label_end])
                state = "exemplarparsedlabels"
            else:
                raise ValueError("Invalid line: " + text)
        elif state == "exemplarparsedlabels":
            if char == "}":
                state = "exemplarvaluespace"
        elif state == "exemplarvaluespace":
            if char == " ":
                state = "exemplarvalue"
            else:
                raise ValueError("Invalid line: " + text)
        elif state == "exemplarvalue":
            if char == " " and not exemplar_value:
                raise ValueError("Invalid line: " + text)
            elif char == " ":
                state = "exemplartimestamp"
            else:
                exemplar_value.append(char)
        elif state == "exemplartimestamp":
            exemplar_timestamp.append(char)

    # Trailing space after value.
    if state == "timestamp" and not timestamp:
        raise ValueError("Invalid line: " + text)

    # Trailing space after value.
    if state == "exemplartimestamp" and not exemplar_timestamp:
        raise ValueError("Invalid line: " + text)

    # Incomplete exemplar.
    if state in [
        "exemplarhash",
        "exemplarspace",
        "exemplarstartoflabels",
        "exemplarparsedlabels",
    ]:
        raise ValueError("Invalid line: " + text)

    ts = _parse_timestamp(timestamp)
    exemplar = None
    if exemplar_labels is not None:
        exemplar_length = sum([len(k) + len(v) for k, v in exemplar_labels.items()])
        if exemplar_length > 128:
            raise ValueError("Exmplar labels are too long: " + text)
        exemplar = Exemplar(
            exemplar_labels,
            _parse_value(exemplar_value),
            _parse_timestamp(exemplar_timestamp),
        )

    return val, ts, exemplar


def _group_for_sample(sample, name, typ):
    if typ == "info":
        # We can't distinguish between groups for info metrics.
        return {}
    if typ == "summary" and sample.name == name:
        d = sample.labels.copy()
        del d["quantile"]
        return d
    if typ == "stateset":
        d = sample.labels.copy()
        del d[name]
        return d
    if typ in ["histogram", "gaugehistogram"] and sample.name == name + "_bucket":
        d = sample.labels.copy()
        del d["le"]
        return d
    return sample.labels


def _check_histogram(samples, name):
    group = None
    timestamp = None

    def do_checks():
        if bucket != float("+Inf"):
            raise ValueError("+Inf bucket missing: " + name)
        if count is not None and value != count:
            raise ValueError("Count does not match +Inf value: " + name)
        if has_sum and count is None:
            raise ValueError("_count must be present if _sum is present: " + name)
        if has_gsum and count is None:
            raise ValueError("_gcount must be present if _gsum is present: " + name)
        if not (has_sum or has_gsum) and count is not None:
            raise ValueError("_sum/_gsum must be present if _count is present: " + name)
        if has_negative_buckets and has_sum:
            raise ValueError("Cannot have _sum with negative buckets: " + name)
        if not has_negative_buckets and has_negative_gsum:
            raise ValueError(
                "Cannot have negative _gsum with non-negative buckets: " + name
            )

    for s in samples:
        suffix = s.name[len(name) :]
        g = _group_for_sample(s, name, "histogram")
        if g != group or s.timestamp != timestamp:
            if group is not None:
                do_checks()
            count = None
            bucket = None
            has_negative_buckets = False
            has_sum = False
            has_gsum = False
            has_negative_gsum = False
            value = 0
        group = g
        timestamp = s.timestamp

        if suffix == "_bucket":
            b = float(s.labels["le"])
            if b < 0:
                has_negative_buckets = True
            if bucket is not None and b <= bucket:
                raise ValueError("Buckets out of order: " + name)
            if s.value < value:
                raise ValueError("Bucket values out of order: " + name)
            bucket = b
            value = s.value
        elif suffix in ["_count", "_gcount"]:
            count = s.value
        elif suffix in ["_sum"]:
            has_sum = True
        elif suffix in ["_gsum"]:
            has_gsum = True
            if s.value < 0:
                has_negative_gsum = True

    if group is not None:
        do_checks()


def text_fd_to_metric_families(fd):
    """Parse Prometheus text format from a file descriptor.

    This is a laxer parser than the main Go parser,
    so successful parsing does not imply that the parsed
    text meets the specification.

    Yields Metric's.
    """
    name = None
    allowed_names = []
    eof = False

    seen_names = set()
    type_suffixes = {
        "counter": ["_total", "_created"],
        "summary": ["", "_count", "_sum", "_created"],
        "histogram": ["_count", "_sum", "_bucket", "_created"],
        "gaugehistogram": ["_gcount", "_gsum", "_bucket"],
        "info": ["_info"],
    }

    def build_metric(name, documentation, typ, unit, samples):
        if typ is None:
            typ = "unknown"
        for suffix in set(type_suffixes.get(typ, []) + [""]):
            if name + suffix in seen_names:
                raise ValueError("Clashing name: " + name + suffix)
            seen_names.add(name + suffix)
        if documentation is None:
            documentation = ""
        if unit is None:
            unit = ""
        if unit and not name.endswith("_" + unit):
            raise ValueError("Unit does not match metric name: " + name)
        if unit and typ in ["info", "stateset"]:
            raise ValueError("Units not allowed for this metric type: " + name)
        if typ in ["histogram", "gaugehistogram"]:
            _check_histogram(samples, name)
        metric = Metric(name, documentation, typ, unit)
        # TODO: check labelvalues are valid utf8
        metric.samples = samples
        return metric

    for line in fd:
        if line[-1] == "\n":
            line = line[:-1]

        if eof:
            raise ValueError("Received line after # EOF: " + line)

        if not line:
            raise ValueError("Received blank line")

        if line == "# EOF":
            eof = True
        elif line.startswith("#"):
            parts = line.split(" ", 3)
            if len(parts) < 4:
                raise ValueError("Invalid line: " + line)
            if parts[2] == name and samples:
                raise ValueError("Received metadata after samples: " + line)
            if parts[2] != name:
                if name is not None:
                    yield build_metric(name, documentation, typ, unit, samples)
                # New metric
                name = parts[2]
                unit = None
                typ = None
                documentation = None
                group = None
                seen_groups = set()
                group_timestamp = None
                group_timestamp_samples = set()
                samples = []
                allowed_names = [parts[2]]

            if parts[1] == "HELP":
                if documentation is not None:
                    raise ValueError("More than one HELP for metric: " + line)
                documentation = _unescape_help(parts[3])
            elif parts[1] == "TYPE":
                if typ is not None:
                    raise ValueError("More than one TYPE for metric: " + line)
                typ = parts[3]
                if typ == "untyped":
                    raise ValueError("Invalid TYPE for metric: " + line)
                allowed_names = [name + n for n in type_suffixes.get(typ, [""])]
            elif parts[1] == "UNIT":
                if unit is not None:
                    raise ValueError("More than one UNIT for metric: " + line)
                unit = parts[3]
            else:
                raise ValueError("Invalid line: " + line)
        else:
            sample = _parse_sample(line)
            if sample.name not in allowed_names:
                if name is not None:
                    yield build_metric(name, documentation, typ, unit, samples)
                # Start an unknown metric.
                name = sample.name
                documentation = None
                unit = None
                typ = "unknown"
                samples = []
                group = None
                group_timestamp = None
                group_timestamp_samples = set()
                seen_groups = set()
                allowed_names = [sample.name]

            if typ == "stateset" and name not in sample.labels:
                raise ValueError("Stateset missing label: " + line)
            if (
                typ in ["histogram", "gaugehistogram"]
                and name + "_bucket" == sample.name
                and (
                    sample.labels.get("le", "NaN") == "NaN"
                    or _isUncanonicalNumber(sample.labels["le"])
                )
            ):
                raise ValueError("Invalid le label: " + line)
            if (
                typ == "summary"
                and name == sample.name
                and (
                    not (0 <= float(sample.labels.get("quantile", -1)) <= 1)
                    or _isUncanonicalNumber(sample.labels["quantile"])
                )
            ):
                raise ValueError("Invalid quantile label: " + line)

            g = tuple(sorted(_group_for_sample(sample, name, typ).items()))
            if group is not None and g != group and g in seen_groups:
                raise ValueError("Invalid metric grouping: " + line)
            if group is not None and g == group:
                if (sample.timestamp is None) != (group_timestamp is None):
                    raise ValueError(
                        "Mix of timestamp presence within a group: " + line
                    )
                if (
                    group_timestamp is not None
                    and group_timestamp > sample.timestamp
                    and typ != "info"
                ):
                    raise ValueError(
                        "Timestamps went backwards within a group: " + line
                    )
            else:
                group_timestamp_samples = set()

            series_id = (sample.name, tuple(sorted(sample.labels.items())))
            if (
                sample.timestamp != group_timestamp
                or series_id not in group_timestamp_samples
            ):
                # Not a duplicate due to timestamp truncation.
                samples.append(sample)
            group_timestamp_samples.add(series_id)

            group = g
            group_timestamp = sample.timestamp
            seen_groups.add(g)

            if typ == "stateset" and sample.value not in [0, 1]:
                raise ValueError(
                    "Stateset samples can only have values zero and one: " + line
                )
            if typ == "info" and sample.value != 1:
                raise ValueError("Info samples can only have value one: " + line)
            if typ == "summary" and name == sample.name and sample.value < 0:
                raise ValueError("Quantile values cannot be negative: " + line)
            if sample.name[len(name) :] in [
                "_total",
                "_sum",
                "_count",
                "_bucket",
                "_gcount",
                "_gsum",
            ] and math.isnan(sample.value):
                raise ValueError("Counter-like samples cannot be NaN: " + line)
            if (
                sample.name[len(name) :]
                in ["_total", "_sum", "_count", "_bucket", "_gcount"]
                and sample.value < 0
            ):
                raise ValueError("Counter-like samples cannot be negative: " + line)
            if sample.exemplar and not (
                (
                    typ in ["histogram", "gaugehistogram"]
                    and sample.name.endswith("_bucket")
                )
                or (typ in ["counter"] and sample.name.endswith("_total"))
            ):
                raise ValueError(
                    "Invalid line only histogram/gaugehistogram buckets and counters can have exemplars: "
                    + line
                )

    if name is not None:
        yield build_metric(name, documentation, typ, unit, samples)

    if not eof:
        raise ValueError("Missing # EOF at end")

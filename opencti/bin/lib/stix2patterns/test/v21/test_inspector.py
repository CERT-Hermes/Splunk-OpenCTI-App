import pytest

from stix2patterns.inspector import INDEX_STAR
from stix2patterns.v21.pattern import Pattern


@pytest.mark.parametrize(
    "pattern,expected_qualifiers",
    [
        ("[foo:bar = 1]", set()),
        ("[foo:bar = 1] REPEATS 5 TIMES", set(["REPEATS 5 TIMES"])),
        ("[foo:bar = 1] WITHIN 10.3 SECONDS", set(["WITHIN 10.3 SECONDS"])),
        ("[foo:bar = 1] WITHIN 123 SECONDS", set(["WITHIN 123 SECONDS"])),
        (
            "[foo:bar = 1] START t'1932-11-12T15:42:15Z' STOP t'1964-10-23T21:12:26Z'",
            set(["START t'1932-11-12T15:42:15Z' STOP t'1964-10-23T21:12:26Z'"]),
        ),
        (
            "[foo:bar = 1] REPEATS 1 TIMES AND [foo:baz = 2] WITHIN 1.23 SECONDS",
            set(["REPEATS 1 TIMES", "WITHIN 1.23 SECONDS"]),
        ),
        (
            "([foo:bar = 1] START t'1932-11-12T15:42:15Z' STOP t'1964-10-23T21:12:26Z' AND [foo:abc < h'12ab']) WITHIN 22 SECONDS "
            "OR [frob:baz NOT IN (1,2,3)] REPEATS 31 TIMES",
            set(
                [
                    "START t'1932-11-12T15:42:15Z' STOP t'1964-10-23T21:12:26Z'",
                    "WITHIN 22 SECONDS",
                    "REPEATS 31 TIMES",
                ]
            ),
        ),
    ],
)
def test_qualifiers(pattern, expected_qualifiers):
    compiled_pattern = Pattern(pattern)
    pattern_data = compiled_pattern.inspect()

    assert pattern_data.qualifiers == expected_qualifiers


@pytest.mark.parametrize(
    "pattern,expected_obs_ops",
    [
        ("[foo:bar = 1]", set()),
        ("[foo:bar = 1] AND [foo:baz > 25.2]", set(["AND"])),
        ("[foo:bar = 1] OR [foo:baz != 'hello']", set(["OR"])),
        ("[foo:bar = 1] FOLLOWEDBY [foo:baz IN (1,2,3)]", set(["FOLLOWEDBY"])),
        ("[foo:bar = 1] AND [foo:baz = 22] OR [foo:abc = '123']", set(["AND", "OR"])),
        (
            "[foo:bar = 1] OR ([foo:baz = false] FOLLOWEDBY [frob:abc LIKE '123']) WITHIN 46.1 SECONDS",
            set(["OR", "FOLLOWEDBY"]),
        ),
    ],
)
def test_observation_ops(pattern, expected_obs_ops):
    compiled_pattern = Pattern(pattern)
    pattern_data = compiled_pattern.inspect()

    assert pattern_data.observation_ops == expected_obs_ops


@pytest.mark.parametrize(
    "pattern,expected_comparisons",
    [
        ("[foo:bar = 1]", {"foo": [(["bar"], "=", "1")]}),
        (
            "[foo:bar=1 AND foo:baz=2]",
            {"foo": [(["bar"], "=", "1"), (["baz"], "=", "2")]},
        ),
        (
            "[foo:bar NOT !=1 OR bar:foo<12.3]",
            {"foo": [(["bar"], "NOT !=", "1")], "bar": [(["foo"], "<", "12.3")]},
        ),
        (
            "[foo:bar=1] OR [foo:baz MATCHES '123\\\\d+']",
            {"foo": [(["bar"], "=", "1"), (["baz"], "MATCHES", "'123\\\\d+'")]},
        ),
        (
            "[foo:bar=1 AND bar:foo NOT >33] REPEATS 12 TIMES OR "
            "  ([baz:bar ISSUBSET '1234'] FOLLOWEDBY [baz:quux NOT LIKE 'a_cd'])",
            {
                "foo": [(["bar"], "=", "1")],
                "bar": [(["foo"], "NOT >", "33")],
                "baz": [
                    (["bar"], "ISSUBSET", "'1234'"),
                    (["quux"], "NOT LIKE", "'a_cd'"),
                ],
            },
        ),
        (
            "[obj-type:a.b[*][1].'c-d' NOT ISSUPERSET '1.2.3.4/16']",
            {
                "obj-type": [
                    (["a", "b", INDEX_STAR, 1, "c-d"], "NOT ISSUPERSET", "'1.2.3.4/16'")
                ]
            },
        ),
    ],
)
def test_comparisons(pattern, expected_comparisons):
    compiled_pattern = Pattern(pattern)
    pattern_data = compiled_pattern.inspect()

    assert pattern_data.comparisons == expected_comparisons

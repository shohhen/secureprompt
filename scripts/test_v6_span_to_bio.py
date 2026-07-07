#!/usr/bin/env python3
"""Standalone unit tests for the v6 data front-end. Run:
    .venv-train/bin/python scripts/test_v6_span_to_bio.py
Exits non-zero on first failure; prints OK when all pass. Also importable by pytest."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from v6_span_to_bio import load_head_labels, spanjsonl_to_bio


def _ents(*triples):
    return [{"label": l, "start": s, "end": e, "value": None} for (l, s, e) in triples]


def test_single_word_entity():
    # "Salom Aziz keldi" -> Aziz is [6,10]
    words, tags = spanjsonl_to_bio("Salom Aziz keldi", _ents(("PERSON", 6, 10)))
    assert words == ["Salom", "Aziz", "keldi"], words
    assert tags == ["O", "B-PERSON", "O"], tags


def test_multi_word_entity():
    words, tags = spanjsonl_to_bio("Maxim Frolov keldi", _ents(("PERSON", 0, 12)))
    assert tags == ["B-PERSON", "I-PERSON", "O"], tags


def test_agglutinated_suffix():
    # entity "APEXBANK" [13,21] sits inside the word "APEXBANKda" [13,23]
    text = "hisob raqami APEXBANKda ochildi"
    words, tags = spanjsonl_to_bio(text, _ents(("ORGANIZATION", 13, 21)))
    i = words.index("APEXBANKda")
    assert tags[i] == "B-ORGANIZATION", (words, tags)


def test_two_adjacent_same_label_split():
    # "Aziz Karim" = TWO separate PERSON entities -> must be B-PERSON B-PERSON
    words, tags = spanjsonl_to_bio("Aziz Karim", _ents(("PERSON", 0, 4), ("PERSON", 5, 10)))
    assert tags == ["B-PERSON", "B-PERSON"], tags


def test_entity_at_start_and_end():
    words, tags = spanjsonl_to_bio("Aziz keldi Toshkent",
                                   _ents(("PERSON", 0, 4), ("ADDRESS", 11, 19)))
    assert tags == ["B-PERSON", "O", "B-ADDRESS"], tags


def test_no_entities():
    words, tags = spanjsonl_to_bio("hech qanday shaxs yoq", [])
    assert tags == ["O", "O", "O", "O"], tags


def test_tie_breaks_to_earliest_entity():
    # single word "AB" [0,2] overlapped 1 char by each of two entities;
    # earliest start (PERSON at 0) wins the tie.
    words, tags = spanjsonl_to_bio("AB", _ents(("ORGANIZATION", 1, 2), ("PERSON", 0, 1)))
    assert tags == ["B-PERSON"], tags


def test_head_matches_v5cold_config():
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    cfg = f"{repo}/secureprompt-ml/app/resources/multilingual_ner_v5_cold_xlmr/model/config.json"
    label2id, id2label = load_head_labels(cfg)
    assert len(id2label) == 85, len(id2label)
    assert id2label[0] == "O"
    assert sorted(id2label) == list(range(85))          # contiguous 0..84
    assert all(label2id[id2label[i]] == i for i in range(85))


def _run():
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for fn in fns:
        fn()
        print(f"  PASS {fn.__name__}")
    print(f"OK ({len(fns)} tests)")


if __name__ == "__main__":
    _run()

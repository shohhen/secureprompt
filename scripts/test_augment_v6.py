import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import augment_v6 as A  # noqa: E402

LANGS = ("ru", "uz_latn", "uz_cyrl")


def test_offsets_correct_by_construction():
    rng = random.Random(0)
    for lang in LANGS:
        for gen in A.CATEGORIES:
            for _ in range(50):
                rec = gen(rng, lang)
                for e in rec["entities"]:
                    assert rec["text"][e["start"]:e["end"]] == e["value"], (
                        gen.__name__, lang, e, rec["text"])


def test_labels_in_valid_set():
    valid = {"PERSON", "ORGANIZATION", "ADDRESS"}
    rng = random.Random(1)
    for lang in LANGS:
        for gen in A.CATEGORIES:
            for _ in range(20):
                for e in gen(rng, lang)["entities"]:
                    assert e["label"] in valid


def test_hardneg_tech_leaves_tech_unlabeled():
    rng = random.Random(2)
    for lang in LANGS:
        for _ in range(20):
            rec = A.gen_hardneg_tech(rng, lang)
            assert {e["label"] for e in rec["entities"]} == {"PERSON"}
            for e in rec["entities"]:
                assert e["value"] not in A.TECH


def test_generator_is_deterministic(tmp_path):
    import subprocess
    root = Path(__file__).resolve().parents[1]
    def run(d):
        subprocess.run([sys.executable, str(root / "scripts" / "augment_v6.py"),
                        "--per-category", "10", "--out-dir", str(d)], check=True)
    a, b = tmp_path / "a", tmp_path / "b"
    run(a); run(b)
    for lang in LANGS:
        fn = f"aug_train_{A.FILE_LANG[lang]}.jsonl"
        assert (a / fn).read_text(encoding="utf-8") == \
               (b / fn).read_text(encoding="utf-8")

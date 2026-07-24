import logging

import pdf_utils


def _use_isolated_cache(monkeypatch, tmp_path):
    cache_dir = tmp_path / "pdf-cache"
    monkeypatch.setenv("PDF_TEXT_CACHE_DIR", str(cache_dir))
    monkeypatch.delenv("PDF_TEXT_CACHE_ENABLED", raising=False)
    return cache_dir


def test_extract_pdf_bytes_prefers_unstructured(monkeypatch, tmp_path):
    _use_isolated_cache(monkeypatch, tmp_path)
    monkeypatch.setattr(pdf_utils, "_partition_pdf", lambda **kwargs: ["first", "second"])
    monkeypatch.setattr(
        pdf_utils,
        "_pypdf_text_from_bytes",
        lambda pdf_bytes: (_ for _ in ()).throw(AssertionError("unexpected fallback")),
    )

    assert pdf_utils.extract_pdf_text_from_bytes(b"pdf") == "first\n\nsecond"


def test_extract_pdf_bytes_logs_and_falls_back(monkeypatch, caplog, tmp_path):
    _use_isolated_cache(monkeypatch, tmp_path)

    def fail_partition(**kwargs):
        raise RuntimeError("optional dependency unavailable")

    monkeypatch.setattr(pdf_utils, "_partition_pdf", fail_partition)
    monkeypatch.setattr(pdf_utils, "_pypdf_text_from_bytes", lambda pdf_bytes: "fallback")

    with caplog.at_level(logging.DEBUG, logger=pdf_utils.__name__):
        assert pdf_utils.extract_pdf_text_from_bytes(b"pdf") == "fallback"

    assert "using pypdf fallback" in caplog.text


def test_extract_pdf_path_logs_and_falls_back(monkeypatch, caplog, tmp_path):
    _use_isolated_cache(monkeypatch, tmp_path)
    pdf_path = tmp_path / "sample.pdf"
    pdf_path.write_bytes(b"pdf")
    monkeypatch.setattr(
        pdf_utils,
        "_partition_pdf",
        lambda **kwargs: (_ for _ in ()).throw(RuntimeError("partition failed")),
    )
    monkeypatch.setattr(pdf_utils, "_pypdf_text_from_bytes", lambda pdf_bytes: "fallback")

    with caplog.at_level(logging.DEBUG, logger=pdf_utils.__name__):
        assert pdf_utils.extract_pdf_text_from_path(pdf_path) == "fallback"

    assert str(pdf_path) in caplog.text


def test_identical_pdf_bytes_reuse_cached_text(monkeypatch, tmp_path):
    cache_dir = _use_isolated_cache(monkeypatch, tmp_path)
    calls = 0

    def partition(**kwargs):
        nonlocal calls
        calls += 1
        return ["cached text"]

    monkeypatch.setattr(pdf_utils, "_partition_pdf", partition)

    assert pdf_utils.extract_pdf_text_from_bytes(b"same pdf") == "cached text"
    assert pdf_utils.extract_pdf_text_from_bytes(b"same pdf") == "cached text"
    assert calls == 1
    cache_files = list(cache_dir.glob("*.txt"))
    assert len(cache_files) == 1
    assert cache_files[0].stat().st_mode & 0o777 == 0o600


def test_pdf_cache_key_changes_with_content(monkeypatch, tmp_path):
    cache_dir = _use_isolated_cache(monkeypatch, tmp_path)
    monkeypatch.setattr(
        pdf_utils,
        "_partition_pdf",
        lambda **kwargs: [kwargs["file"].getvalue().decode()],
    )

    assert pdf_utils.extract_pdf_text_from_bytes(b"first pdf") == "first pdf"
    assert pdf_utils.extract_pdf_text_from_bytes(b"second pdf") == "second pdf"
    assert len(list(cache_dir.glob("*.txt"))) == 2


def test_path_and_bytes_extraction_share_cache(monkeypatch, tmp_path):
    _use_isolated_cache(monkeypatch, tmp_path)
    pdf_path = tmp_path / "sample.pdf"
    pdf_path.write_bytes(b"same pdf")
    calls = 0

    def partition(**kwargs):
        nonlocal calls
        calls += 1
        return ["shared text"]

    monkeypatch.setattr(pdf_utils, "_partition_pdf", partition)

    assert pdf_utils.extract_pdf_text_from_path(pdf_path) == "shared text"
    assert pdf_utils.extract_pdf_text_from_bytes(b"same pdf") == "shared text"
    assert calls == 1


def test_pdf_cache_can_be_disabled(monkeypatch, tmp_path):
    cache_dir = _use_isolated_cache(monkeypatch, tmp_path)
    monkeypatch.setenv("PDF_TEXT_CACHE_ENABLED", "0")
    calls = 0

    def partition(**kwargs):
        nonlocal calls
        calls += 1
        return ["uncached text"]

    monkeypatch.setattr(pdf_utils, "_partition_pdf", partition)

    assert pdf_utils.extract_pdf_text_from_bytes(b"pdf") == "uncached text"
    assert pdf_utils.extract_pdf_text_from_bytes(b"pdf") == "uncached text"
    assert calls == 2
    assert not cache_dir.exists()


def test_corrupt_pdf_cache_entry_is_regenerated(monkeypatch, tmp_path):
    cache_dir = _use_isolated_cache(monkeypatch, tmp_path)
    cache_path = pdf_utils._cache_path(b"pdf")
    cache_dir.mkdir()
    cache_path.write_bytes(b"\xff")
    monkeypatch.setattr(pdf_utils, "_partition_pdf", lambda **kwargs: ["fresh text"])

    assert pdf_utils.extract_pdf_text_from_bytes(b"pdf") == "fresh text"
    assert cache_path.read_text(encoding="utf-8") == "fresh text"

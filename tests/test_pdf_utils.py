import logging

import pdf_utils


def test_extract_pdf_bytes_prefers_unstructured(monkeypatch):
    monkeypatch.setattr(pdf_utils, "_partition_pdf", lambda **kwargs: ["first", "second"])
    monkeypatch.setattr(
        pdf_utils,
        "_pypdf_text_from_bytes",
        lambda pdf_bytes: (_ for _ in ()).throw(AssertionError("unexpected fallback")),
    )

    assert pdf_utils.extract_pdf_text_from_bytes(b"pdf") == "first\n\nsecond"


def test_extract_pdf_bytes_logs_and_falls_back(monkeypatch, caplog):
    def fail_partition(**kwargs):
        raise RuntimeError("optional dependency unavailable")

    monkeypatch.setattr(pdf_utils, "_partition_pdf", fail_partition)
    monkeypatch.setattr(pdf_utils, "_pypdf_text_from_bytes", lambda pdf_bytes: "fallback")

    with caplog.at_level(logging.DEBUG, logger=pdf_utils.__name__):
        assert pdf_utils.extract_pdf_text_from_bytes(b"pdf") == "fallback"

    assert "using pypdf fallback" in caplog.text


def test_extract_pdf_path_logs_and_falls_back(monkeypatch, caplog, tmp_path):
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

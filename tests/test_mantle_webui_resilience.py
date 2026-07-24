import asyncio
import importlib.util
from pathlib import Path


MODULE_PATH = (
    Path(__file__).resolve().parents[1]
    / "examples"
    / "cybersecurity"
    / "13_mantle_gpt55_cybersec_webui.py"
)


def load_module():
    spec = importlib.util.spec_from_file_location("mantle_webui_13", MODULE_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FakeEvent:
    def __init__(self, event_type: str, delta: str | None = None):
        self.type = event_type
        self.delta = delta


class FakeStream:
    def __init__(self, events):
        self._events = iter(events)

    def __aiter__(self):
        return self

    async def __anext__(self):
        try:
            return next(self._events)
        except StopIteration:
            raise StopAsyncIteration from None


class FakeResponses:
    def __init__(self, outcome, calls):
        self._outcome = outcome
        self._calls = calls

    async def create(self, **kwargs):
        self._calls.append(kwargs)
        if isinstance(self._outcome, BaseException):
            raise self._outcome
        return self._outcome


class FakeClient:
    def __init__(self, outcome, calls):
        self.responses = FakeResponses(outcome, calls)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return None


def test_transient_mantle_statuses_are_retryable():
    module = load_module()

    for status in (408, 429, 500, 502, 503, 504):
        exc = RuntimeError("request failed")
        exc.status_code = status
        assert module._is_transient_model_error(exc)

    exc = RuntimeError("bad request")
    exc.status_code = 400
    assert not module._is_transient_model_error(exc)


def test_run_model_retries_before_streaming(monkeypatch):
    module = load_module()
    calls = []
    outcomes = [
        RuntimeError("internal_server_error"),
        FakeStream(
            [
                FakeEvent("response.created"),
                FakeEvent("response.output_text.delta", "Hello"),
                FakeEvent("response.output_text.delta", " world"),
            ]
        ),
    ]

    monkeypatch.setattr(
        module,
        "_make_client",
        lambda: FakeClient(outcomes.pop(0), calls),
    )
    monkeypatch.setattr(module, "RETRY_BASE_SECONDS", 0)

    async def collect():
        return [
            text
            async for text in module._run_model(
                "openai.gpt-5.5",
                [{"text": "test"}],
                max_attempts=2,
            )
        ]

    assert asyncio.run(collect()) == ["Hello", " world"]
    assert len(calls) == 2
    assert all(call["stream"] is True for call in calls)
    assert all(call["max_output_tokens"] == module.MAX_OUTPUT_TOKENS for call in calls)


def test_heartbeat_wrapper_keeps_idle_stream_alive(monkeypatch):
    module = load_module()
    monkeypatch.setattr(module, "HEARTBEAT_SECONDS", 0.01)

    async def delayed_source():
        await asyncio.sleep(0.025)
        yield "ready"

    async def collect():
        return [value async for value in module._with_heartbeats(delayed_source())]

    values = asyncio.run(collect())
    assert values[-1] == "ready"
    assert None in values[:-1]


def test_safe_stream_propagates_cancellation_without_yielding_done(monkeypatch):
    module = load_module()

    async def exercise():
        started = asyncio.Event()
        release = asyncio.Event()

        async def hanging_stream(*_args, **_kwargs):
            started.set()
            await release.wait()
            yield module._sse({"type": "done"})

        monkeypatch.setattr(module, "_stream_request_analysis", hanging_stream)
        stream = module._safe_stream_request_analysis([], "", module.PRIMARY_MODEL)
        pending = asyncio.create_task(anext(stream))
        await started.wait()
        pending.cancel()
        try:
            await pending
        except asyncio.CancelledError:
            pass
        else:
            raise AssertionError("stream cancellation was suppressed")
        await stream.aclose()

    asyncio.run(exercise())


def test_graceful_shutdown_timeout_is_bounded():
    module = load_module()

    assert module.GRACEFUL_SHUTDOWN_SECONDS == 5.0
    assert "timeout_graceful_shutdown=GRACEFUL_SHUTDOWN_SECONDS" in MODULE_PATH.read_text()


def test_documented_model_picker_ids_are_allowlisted():
    module = load_module()

    assert module.MANTLE_MODEL_IDS == {
        "openai.gpt-5.6-sol",
        "openai.gpt-5.6-terra",
        "openai.gpt-5.6-luna",
        "openai.gpt-5.5",
        "openai.gpt-5.4",
    }
    assert '<details class="model-picker"' in module.HTML_PAGE
    assert '<select id="model-input">' not in module.HTML_PAGE
    assert module.HTML_PAGE.count('class="model-option"') == 5

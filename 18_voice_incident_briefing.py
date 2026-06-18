"""
Hello World: Strands Voice + Realtime — spoken incident briefing
Uses experimental bidirectional streaming with Amazon Nova Sonic.

Requires Python 3.12+, microphone/speaker access, and bidirectional extras:
  uv add "strands-agents[bidi]"

SSO: aws sso login --profile my-sso-profile && export AWS_PROFILE=my-sso-profile
Run: uv run python 18_voice_incident_briefing.py
     uv run python 18_voice_incident_briefing.py --list-devices
     uv run python 18_voice_incident_briefing.py --text-output-only
     uv run python 18_voice_incident_briefing.py --input-device 1 --output-device 2

Important: BidiAudioIO uses PyAudio, which does not provide echo cancellation.
Use headphones/headset audio. If the Mac speakers play the assistant response
near the microphone, Nova Sonic may hear itself and interrupt its own answer.

Try saying:
  "Brief me on a ransomware advisory."
  "What time is it?"
  "Stop."
"""
import argparse
import asyncio
import os

import boto3

REGION = "us-east-1"  # Nova Sonic is available in us-east-1, eu-north-1, ap-northeast-1.


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--list-devices", action="store_true", help="List PyAudio devices and exit.")
    parser.add_argument("--input-device", type=int, help="PyAudio input device index.")
    parser.add_argument("--output-device", type=int, help="PyAudio output device index.")
    parser.add_argument(
        "--text-output-only",
        action="store_true",
        help="Print transcripts but do not play assistant audio. Useful to avoid feedback while debugging.",
    )
    return parser.parse_args()


def list_devices() -> None:
    try:
        import pyaudio
    except ModuleNotFoundError as exc:
        raise SystemExit(
            "Missing 'pyaudio'. Install bidirectional/audio extras first:\n"
            '  uv add "strands-agents[bidi]"'
        ) from exc

    audio = pyaudio.PyAudio()
    try:
        for index in range(audio.get_device_count()):
            info = audio.get_device_info_by_index(index)
            inputs = int(info.get("maxInputChannels", 0))
            outputs = int(info.get("maxOutputChannels", 0))
            print(f"{index}: {info.get('name')} (inputs={inputs}, outputs={outputs})")
    finally:
        audio.terminate()


async def main() -> None:
    args = parse_args()
    if args.list_devices:
        list_devices()
        return

    try:
        from strands.experimental.bidi import BidiAgent
        from strands.experimental.bidi.io import BidiAudioIO, BidiTextIO
        from strands.experimental.bidi.models import BidiNovaSonicModel
        from strands_tools import current_time, stop
    except ModuleNotFoundError as exc:
        missing = exc.name or "an optional bidirectional streaming dependency"
        raise SystemExit(
            f"Missing {missing!r}. Install bidirectional/audio extras first:\n"
            '  uv add "strands-agents[bidi]"\n'
            "PyAudio may also require system PortAudio headers on macOS."
        ) from exc

    profile = os.environ.get("AWS_PROFILE")
    boto_session = boto3.Session(profile_name=profile, region_name=REGION)
    model = BidiNovaSonicModel(
        model_id="amazon.nova-sonic-v1:0",
        provider_config={"audio": {"voice": "tiffany"}},
        client_config={"boto_session": boto_session},
    )

    agent = BidiAgent(
        model=model,
        tools=[current_time, stop],
        system_prompt=(
            "You are a calm cyber incident briefing assistant. Keep spoken answers very "
            "short: 2-4 sentences unless the user asks for more. Use current_time when timing matters. "
            "Use the stop tool when the user asks to end the session."
        ),
    )

    audio_config = {}
    if args.input_device is not None:
        audio_config["input_device_index"] = args.input_device
    if args.output_device is not None:
        audio_config["output_device_index"] = args.output_device

    audio_io = BidiAudioIO(**audio_config)
    text_io = BidiTextIO()
    outputs = [text_io.output()] if args.text_output_only else [audio_io.output(), text_io.output()]

    if not args.text_output_only:
        print(
            "Audio feedback warning: use headphones/headset audio. "
            "Speakers near the microphone can cause self-interruptions.\n"
        )

    await agent.run(inputs=[audio_io.input()], outputs=outputs)


if __name__ == "__main__":
    asyncio.run(main())

"""
Shared auth helper for bedrock-mantle endpoints.

Wraps a boto3 Session (which respects AWS_PROFILE / named profiles / SSO)
into a CredentialProvider that aws-bedrock-token-generator can consume.
Call `get_mantle_token(region)` to get a fresh bearer token for the given region.
"""
import os
from datetime import datetime, timedelta, timezone
import boto3
from botocore.credentials import CredentialProvider
from aws_bedrock_token_generator import provide_token

TOKEN_TTL = timedelta(hours=12)
TOKEN_REFRESH_MARGIN = timedelta(minutes=5)
_TOKEN_CACHE: dict[str, tuple[str, datetime]] = {}


def _make_session(region: str) -> boto3.Session:
    profile = os.environ.get("AWS_PROFILE")
    return boto3.Session(profile_name=profile, region_name=region)


class BotoSessionCredentialsProvider(CredentialProvider):
    """Adapts a boto3.Session into the CredentialProvider interface expected
    by aws-bedrock-token-generator, so SSO / named profiles work."""

    def __init__(self, session: boto3.Session):
        self._session = session

    def load(self):
        return self._session.get_credentials()


def get_mantle_token(region: str) -> str:
    """Return a bearer token for the bedrock-mantle endpoint in the given region.
    Resolves credentials from AWS_PROFILE (or the default credential chain)."""
    now = datetime.now(timezone.utc)
    cached = _TOKEN_CACHE.get(region)
    if cached:
        token, expires_at = cached
        if now < expires_at - TOKEN_REFRESH_MARGIN:
            return token

    session = _make_session(region)
    provider = BotoSessionCredentialsProvider(session)
    token = provide_token(region=region, aws_credentials_provider=provider, expiry=TOKEN_TTL)
    _TOKEN_CACHE[region] = (token, now + TOKEN_TTL)
    return token

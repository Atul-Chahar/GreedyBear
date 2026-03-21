# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed

from greedybear.models import EventSource


class EventSourceAuthentication(BaseAuthentication):
    keyword = "Bearer"

    def authenticate(self, request):
        auth_header = request.META.get("HTTP_AUTHORIZATION", "")
        if not auth_header.startswith(f"{self.keyword} "):
            return None

        raw_token = auth_header.split(" ", 1)[1].strip()
        if not raw_token:
            raise AuthenticationFailed("Missing token.")

        token_hash = EventSource.hash_token(raw_token)
        try:
            source = EventSource.objects.select_related("owner").get(token_hash=token_hash)
        except EventSource.DoesNotExist as exc:
            raise AuthenticationFailed("Invalid token.") from exc

        return (source.owner, source)

    def authenticate_header(self, request):
        return self.keyword

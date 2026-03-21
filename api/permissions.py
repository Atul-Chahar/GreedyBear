# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
from rest_framework.permissions import BasePermission

from greedybear.models import EventSource


class IsActiveEventSource(BasePermission):
    message = "Inactive event source."

    def has_permission(self, request, view):
        return isinstance(request.auth, EventSource) and request.auth.is_active

from enum import Enum
from typing import Any


def normalize(segment: Any) -> str:
    """Normalize the URL."""
    if isinstance(segment, Enum):
        segment = segment.value
    return str(segment).strip("/")


def urljoin(*args) -> str:
    """Joins given arguments into a url.

    Returns:
        str:
        Joined url.
    """
    return "/".join(map(lambda x: normalize(x), args))

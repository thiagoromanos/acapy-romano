"""Message type identifiers for Revocation Notification protocol."""

from ....messaging.util import get_proto_default_version
from ...didcomm_prefix import DIDCommPrefix
from ..definition import versions

SPEC_URI = (
    "https://github.com/hyperledger/aries-rfcs/blob/main/features/"
    "0721-revocation-notification-v2/README.md"
)

CURRENT_VERSION = get_proto_default_version(versions, 2)
REV_NOTIF_2_0 = "revocation_notification/2.0"
PROTOCOL = "revocation_notification"
BASE = f"{PROTOCOL}/{CURRENT_VERSION}"

# Message types
REVOKE = f"{BASE}/revoke"
UNREVOKE = f"{BASE}/unrevoke"

PROTOCOL_PACKAGE = "aries_cloudagent.protocols.revocation_notification.v2_0"
MESSAGE_TYPES = DIDCommPrefix.qualify_all(
    {
        REVOKE: f"{PROTOCOL_PACKAGE}.messages.revoke.Revoke",
        UNREVOKE: f"{PROTOCOL_PACKAGE}.messages.unrevoke.Unrevoke",
    }
)

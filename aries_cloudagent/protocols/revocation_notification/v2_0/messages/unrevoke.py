"""Revoke message."""

from marshmallow import fields, validate

from .....messaging.agent_message import AgentMessage, AgentMessageSchema
from .....messaging.decorators.please_ack_decorator import (
    PleaseAckDecorator,
    PleaseAckDecoratorSchema,
)
from .....messaging.valid import UUID4_EXAMPLE
from ..message_types import PROTOCOL_PACKAGE, UNREVOKE

HANDLER_CLASS = f"{PROTOCOL_PACKAGE}.handlers.revoke_handler.RevokeHandler"


class Unrevoke(AgentMessage):
    """Class representing revoke message."""

    class Meta:
        """Revoke Meta."""

        handler_class = HANDLER_CLASS
        message_type = UNREVOKE
        schema_class = "UnrevokeSchema"

    def __init__(
        self,
        *,
        revocation_format: str,
        credential_id: str,
        please_ack: PleaseAckDecorator = None,
        comment: str = None,
        **kwargs,
    ):
        """Initialize revoke message."""
        super().__init__(**kwargs)
        self.revocation_format = revocation_format
        self.credential_id = credential_id
        self.comment = comment


class UnrevokeSchema(AgentMessageSchema):
    """Schema of Revoke message."""

    class Meta:
        """RevokeSchema Meta."""

        model_class = Unrevoke

    revocation_format = fields.Str(
        required=True,
        validate=validate.OneOf(["indy-anoncreds", "anoncreds"]),
        metadata={
            "description": "The format of the credential unrevocation ID",
            "example": "indy-anoncreds",
        },
    )
    credential_id = fields.Str(
        required=True,
        metadata={
            "description": "Credential ID of the issued credential to be unrevoked",
            "example": UUID4_EXAMPLE,
        },
    )
    please_ack = fields.Nested(
        PleaseAckDecoratorSchema,
        required=False,
        data_key="~please_ack",
        metadata={
            "description": "Whether or not the holder should acknowledge receipt"
        },
    )
    comment = fields.Str(
        required=False,
        metadata={
            "description": "Human readable information about unrevocation notification"
        },
    )

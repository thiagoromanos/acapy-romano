import json
import logging
from typing import List, Tuple

from web3 import Web3
from web3.contract.contract import ContractFunction
from web3.middleware import geth_poa_middleware
from web3.types import TxReceipt

from aries_cloudagent.wallet.base import BaseWallet

from ..cache.base import BaseCache
from ..core.profile import Profile
from ..ledger.base import BaseLedger
from ..ledger.endpoint_type import EndpointType
from ..ledger.error import LedgerError, LedgerObjectAlreadyExistsError
from ..wallet.did_info import DIDInfo

LOGGER = logging.getLogger(__name__)

CREDENTIAL_DEFINITION_REGISTRY = "CredentialDefinitionRegistry"
SCHEMA_REGISTRY = "SchemaRegistry"
REVOCATION_REGISTRY = "RevocationRegistry"


class BesuVDRWeb3Config:
    """Configurations."""

    def __init__(
        self,
        ledgerAddr: str,
        contractAddrs: dict,
        trusteeAccount: str = None,
        trusteePKey: str = None,
    ) -> None:
        """Configurations for Besu VDR."""
        self.ledgerAddr = ledgerAddr
        self.trusteeAccount = trusteeAccount
        self.trusteePKey = trusteePKey
        self.contractAddrs = contractAddrs
        self.contractAbis = {}

    @property
    def read_only(self) -> bool:
        """If the access is readOnly."""
        return self.trusteeAccount and self.trusteePKey

    def loadConfigs(self):
        """Load the abis (TODO: load from file)."""
        self.contractAbis[CREDENTIAL_DEFINITION_REGISTRY] = json.loads(
            '[{"inputs":[{"internalType":"address","name":"target","type":"address"}],"name":"AddressEmptyCode","type":"error"},{"inputs":[{"internalType":"string","name":"id","type":"string"}],"name":"CredentialDefinitionAlreadyExist","type":"error"},{"inputs":[{"internalType":"string","name":"id","type":"string"}],"name":"CredentialDefinitionNotFound","type":"error"},{"inputs":[{"internalType":"address","name":"implementation","type":"address"}],"name":"ERC1967InvalidImplementation","type":"error"},{"inputs":[],"name":"ERC1967NonPayable","type":"error"},{"inputs":[],"name":"FailedInnerCall","type":"error"},{"inputs":[{"internalType":"string","name":"name","type":"string"}],"name":"FieldRequired","type":"error"},{"inputs":[],"name":"InvalidInitialization","type":"error"},{"inputs":[{"internalType":"string","name":"id","type":"string"}],"name":"InvalidIssuerId","type":"error"},{"inputs":[{"internalType":"string","name":"id","type":"string"}],"name":"IssuerHasBeenDeactivated","type":"error"},{"inputs":[{"internalType":"string","name":"id","type":"string"}],"name":"IssuerNotFound","type":"error"},{"inputs":[],"name":"NotInitializing","type":"error"},{"inputs":[],"name":"PackedPtrLen__LenOverflow","type":"error"},{"inputs":[],"name":"PackedPtrLen__PtrOverflow","type":"error"},{"inputs":[{"internalType":"address","name":"sender","type":"address"},{"internalType":"address","name":"owner","type":"address"}],"name":"SenderIsNotIssuerDidOwner","type":"error"},{"inputs":[],"name":"UUPSUnauthorizedCallContext","type":"error"},{"inputs":[{"internalType":"bytes32","name":"slot","type":"bytes32"}],"name":"UUPSUnsupportedProxiableUUID","type":"error"},{"inputs":[{"internalType":"string","name":"credDefType","type":"string"}],"name":"UnsupportedCredentialDefinitionType","type":"error"},{"anonymous":false,"inputs":[{"indexed":false,"internalType":"string","name":"credentialDefinitionId","type":"string"},{"indexed":true,"internalType":"address","name":"sender","type":"address"}],"name":"CredentialDefinitionCreated","type":"event"},{"anonymous":false,"inputs":[{"indexed":false,"internalType":"uint64","name":"version","type":"uint64"}],"name":"Initialized","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"implementation","type":"address"}],"name":"Upgraded","type":"event"},{"anonymous":false,"inputs":[{"indexed":false,"internalType":"string","name":"reason","type":"string"}],"name":"testError","type":"event"},{"inputs":[],"name":"UPGRADE_INTERFACE_VERSION","outputs":[{"internalType":"string","name":"","type":"string"}],"stateMutability":"view","type":"function"},{"inputs":[{"components":[{"internalType":"string","name":"id","type":"string"},{"internalType":"string","name":"issuerId","type":"string"},{"internalType":"string","name":"schemaId","type":"string"},{"internalType":"string","name":"credDefType","type":"string"},{"internalType":"string","name":"tag","type":"string"},{"internalType":"string","name":"value","type":"string"}],"internalType":"struct CredentialDefinition","name":"credDef","type":"tuple"}],"name":"createCredentialDefinition","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"upgradeControlAddress","type":"address"},{"internalType":"address","name":"didResolverAddress","type":"address"},{"internalType":"address","name":"schemaRegistryAddress","type":"address"}],"name":"initialize","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"proxiableUUID","outputs":[{"internalType":"bytes32","name":"","type":"bytes32"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"string","name":"id","type":"string"}],"name":"resolveCredentialDefinition","outputs":[{"components":[{"components":[{"internalType":"string","name":"id","type":"string"},{"internalType":"string","name":"issuerId","type":"string"},{"internalType":"string","name":"schemaId","type":"string"},{"internalType":"string","name":"credDefType","type":"string"},{"internalType":"string","name":"tag","type":"string"},{"internalType":"string","name":"value","type":"string"}],"internalType":"struct CredentialDefinition","name":"credDef","type":"tuple"},{"components":[{"internalType":"uint256","name":"created","type":"uint256"}],"internalType":"struct CredentialDefinitionMetadata","name":"metadata","type":"tuple"}],"internalType":"struct CredentialDefinitionWithMetadata","name":"credDefWithMetadata","type":"tuple"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"newImplementation","type":"address"},{"internalType":"bytes","name":"data","type":"bytes"}],"name":"upgradeToAndCall","outputs":[],"stateMutability":"payable","type":"function"}]'
        )
        self.contractAbis[SCHEMA_REGISTRY] = json.loads(
            '[{"inputs":[{"internalType":"address","name":"target","type":"address"}],"name":"AddressEmptyCode","type":"error"},{"inputs":[{"internalType":"address","name":"implementation","type":"address"}],"name":"ERC1967InvalidImplementation","type":"error"},{"inputs":[],"name":"ERC1967NonPayable","type":"error"},{"inputs":[],"name":"FailedInnerCall","type":"error"},{"inputs":[{"internalType":"string","name":"name","type":"string"}],"name":"FieldRequired","type":"error"},{"inputs":[],"name":"InvalidInitialization","type":"error"},{"inputs":[{"internalType":"string","name":"id","type":"string"}],"name":"InvalidIssuerId","type":"error"},{"inputs":[{"internalType":"string","name":"id","type":"string"}],"name":"InvalidSchemaId","type":"error"},{"inputs":[{"internalType":"string","name":"id","type":"string"}],"name":"IssuerHasBeenDeactivated","type":"error"},{"inputs":[{"internalType":"string","name":"id","type":"string"}],"name":"IssuerNotFound","type":"error"},{"inputs":[],"name":"NotInitializing","type":"error"},{"inputs":[],"name":"PackedPtrLen__LenOverflow","type":"error"},{"inputs":[],"name":"PackedPtrLen__PtrOverflow","type":"error"},{"inputs":[{"internalType":"string","name":"id","type":"string"}],"name":"SchemaAlreadyExist","type":"error"},{"inputs":[{"internalType":"string","name":"id","type":"string"}],"name":"SchemaNotFound","type":"error"},{"inputs":[{"internalType":"address","name":"sender","type":"address"},{"internalType":"address","name":"owner","type":"address"}],"name":"SenderIsNotIssuerDidOwner","type":"error"},{"inputs":[],"name":"UUPSUnauthorizedCallContext","type":"error"},{"inputs":[{"internalType":"bytes32","name":"slot","type":"bytes32"}],"name":"UUPSUnsupportedProxiableUUID","type":"error"},{"anonymous":false,"inputs":[{"indexed":false,"internalType":"uint64","name":"version","type":"uint64"}],"name":"Initialized","type":"event"},{"anonymous":false,"inputs":[{"indexed":false,"internalType":"string","name":"schemaId","type":"string"},{"indexed":true,"internalType":"address","name":"sender","type":"address"}],"name":"SchemaCreated","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"implementation","type":"address"}],"name":"Upgraded","type":"event"},{"anonymous":false,"inputs":[{"indexed":false,"internalType":"string","name":"reason","type":"string"}],"name":"testError","type":"event"},{"inputs":[],"name":"UPGRADE_INTERFACE_VERSION","outputs":[{"internalType":"string","name":"","type":"string"}],"stateMutability":"view","type":"function"},{"inputs":[{"components":[{"internalType":"string","name":"id","type":"string"},{"internalType":"string","name":"issuerId","type":"string"},{"internalType":"string","name":"name","type":"string"},{"internalType":"string","name":"version","type":"string"},{"internalType":"string[]","name":"attrNames","type":"string[]"}],"internalType":"struct Schema","name":"schema","type":"tuple"}],"name":"createSchema","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"upgradeControlAddress","type":"address"},{"internalType":"address","name":"didResolverAddress","type":"address"}],"name":"initialize","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"proxiableUUID","outputs":[{"internalType":"bytes32","name":"","type":"bytes32"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"string","name":"id","type":"string"}],"name":"resolveSchema","outputs":[{"components":[{"components":[{"internalType":"string","name":"id","type":"string"},{"internalType":"string","name":"issuerId","type":"string"},{"internalType":"string","name":"name","type":"string"},{"internalType":"string","name":"version","type":"string"},{"internalType":"string[]","name":"attrNames","type":"string[]"}],"internalType":"struct Schema","name":"schema","type":"tuple"},{"components":[{"internalType":"uint256","name":"created","type":"uint256"}],"internalType":"struct SchemaMetadata","name":"metadata","type":"tuple"}],"internalType":"struct SchemaWithMetadata","name":"schemaWithMetadata","type":"tuple"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"newImplementation","type":"address"},{"internalType":"bytes","name":"data","type":"bytes"}],"name":"upgradeToAndCall","outputs":[],"stateMutability":"payable","type":"function"}]'
        )
        self.contractAbis[REVOCATION_REGISTRY] = json.loads(
            '[{"inputs":[{"internalType":"address","name":"target","type":"address"}],"name":"AddressEmptyCode","type":"error"},{"inputs":[{"internalType":"address","name":"implementation","type":"address"}],"name":"ERC1967InvalidImplementation","type":"error"},{"inputs":[],"name":"ERC1967NonPayable","type":"error"},{"inputs":[],"name":"FailedInnerCall","type":"error"},{"inputs":[],"name":"InvalidInitialization","type":"error"},{"inputs":[{"internalType":"string","name":"id","type":"string"}],"name":"InvalidIssuerId","type":"error"},{"inputs":[{"internalType":"string","name":"id","type":"string"}],"name":"IssuerHasBeenDeactivated","type":"error"},{"inputs":[{"internalType":"string","name":"id","type":"string"}],"name":"IssuerNotFound","type":"error"},{"inputs":[],"name":"NotInitializing","type":"error"},{"inputs":[{"internalType":"string","name":"id","type":"string"}],"name":"RevocationAlreadyExist","type":"error"},{"inputs":[{"internalType":"string","name":"id","type":"string"}],"name":"RevocationNotFound","type":"error"},{"inputs":[{"internalType":"address","name":"sender","type":"address"},{"internalType":"address","name":"creator","type":"address"}],"name":"SenderIsNotCreator","type":"error"},{"inputs":[{"internalType":"address","name":"sender","type":"address"},{"internalType":"address","name":"owner","type":"address"}],"name":"SenderIsNotIssuerDidOwner","type":"error"},{"inputs":[],"name":"UUPSUnauthorizedCallContext","type":"error"},{"inputs":[{"internalType":"bytes32","name":"slot","type":"bytes32"}],"name":"UUPSUnsupportedProxiableUUID","type":"error"},{"anonymous":false,"inputs":[{"indexed":false,"internalType":"string","name":"RevocationId","type":"string"},{"indexed":true,"internalType":"address","name":"sender","type":"address"}],"name":"CredentialRevoked","type":"event"},{"anonymous":false,"inputs":[{"indexed":false,"internalType":"string","name":"RevocationId","type":"string"},{"indexed":true,"internalType":"address","name":"sender","type":"address"}],"name":"CredentialUnrevoked","type":"event"},{"anonymous":false,"inputs":[{"indexed":false,"internalType":"uint64","name":"version","type":"uint64"}],"name":"Initialized","type":"event"},{"anonymous":false,"inputs":[{"indexed":false,"internalType":"string","name":"RevRegId","type":"string"},{"indexed":true,"internalType":"address","name":"sender","type":"address"}],"name":"RevListCreated","type":"event"},{"anonymous":false,"inputs":[{"indexed":false,"internalType":"string","name":"RevocationId","type":"string"},{"indexed":true,"internalType":"address","name":"sender","type":"address"}],"name":"RevocationCreated","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"implementation","type":"address"}],"name":"Upgraded","type":"event"},{"inputs":[],"name":"UPGRADE_INTERFACE_VERSION","outputs":[{"internalType":"string","name":"","type":"string"}],"stateMutability":"view","type":"function"},{"inputs":[{"components":[{"internalType":"string","name":"revDefId","type":"string"},{"internalType":"string","name":"regDefType","type":"string"},{"internalType":"string","name":"entry","type":"string"},{"internalType":"string","name":"issuerId","type":"string"}],"internalType":"struct RevocationRegEntry","name":"revEntry","type":"tuple"}],"name":"createOrUpdateEntry","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"components":[{"internalType":"string","name":"id","type":"string"},{"internalType":"string","name":"issuerId","type":"string"},{"internalType":"string","name":"credDefId","type":"string"}],"internalType":"struct Revocation","name":"_revocation","type":"tuple"}],"name":"createRevocation","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"components":[{"internalType":"string","name":"ver","type":"string"},{"internalType":"string","name":"id","type":"string"},{"internalType":"string","name":"revocDefType","type":"string"},{"internalType":"string","name":"credDefId","type":"string"},{"internalType":"string","name":"tag","type":"string"},{"internalType":"string","name":"value","type":"string"},{"internalType":"string","name":"issuerId","type":"string"}],"internalType":"struct RevocationReg","name":"revRegistry","type":"tuple"}],"name":"createRevocationRegistry","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"upgradeControlAddress","type":"address"},{"internalType":"address","name":"didResolverAddress","type":"address"},{"internalType":"address","name":"credDefRegistryAddress","type":"address"}],"name":"initialize","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"proxiableUUID","outputs":[{"internalType":"bytes32","name":"","type":"bytes32"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"string","name":"id","type":"string"}],"name":"resolveEntry","outputs":[{"components":[{"components":[{"internalType":"string","name":"revDefId","type":"string"},{"internalType":"string","name":"regDefType","type":"string"},{"internalType":"string","name":"entry","type":"string"},{"internalType":"string","name":"issuerId","type":"string"}],"internalType":"struct RevocationRegEntry","name":"revEntry","type":"tuple"},{"components":[{"internalType":"uint256","name":"created","type":"uint256"},{"internalType":"address","name":"creator","type":"address"},{"internalType":"uint256","name":"updated","type":"uint256"}],"internalType":"struct RevocationEntryMetadata","name":"metadata","type":"tuple"}],"internalType":"struct RevocationEntryWithMetadata","name":"revEntryMetadata","type":"tuple"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"string","name":"id","type":"string"}],"name":"resolveRevocation","outputs":[{"components":[{"components":[{"internalType":"string","name":"ver","type":"string"},{"internalType":"string","name":"id","type":"string"},{"internalType":"string","name":"revocDefType","type":"string"},{"internalType":"string","name":"credDefId","type":"string"},{"internalType":"string","name":"tag","type":"string"},{"internalType":"string","name":"value","type":"string"},{"internalType":"string","name":"issuerId","type":"string"}],"internalType":"struct RevocationReg","name":"revocationReg","type":"tuple"},{"components":[{"internalType":"uint256","name":"created","type":"uint256"},{"internalType":"address","name":"creator","type":"address"},{"internalType":"uint256","name":"updated","type":"uint256"}],"internalType":"struct RevocationRegMetadata","name":"metadata","type":"tuple"}],"internalType":"struct RevocationRegWithMetadata","name":"revWithMetadata","type":"tuple"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"string","name":"id","type":"string"}],"name":"revokeCredential","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"newImplementation","type":"address"},{"internalType":"bytes","name":"data","type":"bytes"}],"name":"upgradeToAndCall","outputs":[],"stateMutability":"payable","type":"function"}]'
        )


class BesuVdrLedger(BaseLedger):
    """Handles Besu ledger."""

    BACKEND_NAME = "besu-vdr"

    def __init__(
        self,
        ledgerConfig: BesuVDRWeb3Config,
        profile: Profile,
        cache: BaseCache = None,
        cache_duration: int = 600,
    ) -> None:
        """Initialize BesuVDR ledger."""
        self.ledgerConfig = ledgerConfig
        self.cache = cache
        self.profile = profile
        self.cache_duration = cache_duration

    def is_ledger_read_only(self) -> bool:
        """If is read-only."""
        return self.ledgerConfig.read_only

    @property
    def read_only(self) -> bool:
        """Accessor for the ledger read-only flag."""
        return self.is_ledger_read_only()

    async def __aenter__(self) -> "BesuVdrLedger":
        """Context enter."""
        LOGGER.debug("Loading abis...")
        self.ledgerConfig.loadConfigs()
        LOGGER.debug("Initializing web3...")
        self.web3 = Web3(Web3.HTTPProvider(self.ledgerConfig.ledgerAddr))
        self.web3.middleware_onion.inject(geth_poa_middleware, layer=0)
        LOGGER.debug(f"Web3 initialized. Provider addr: {self.ledgerConfig.ledgerAddr}")
        return self

    async def get_schema(self, schema_id: str) -> dict:
        """Get schema from ledger."""
        if self.cache:
            result = await self.cache.get(f"schema::{schema_id}")
            if result:
                return result

        if schema_id.isdigit():
            return await self.fetch_schema_by_seq_no(schema_id)
        else:
            return await self.fetch_schema_by_id(schema_id)

    async def fetch_schema_by_id(self, schema_id: str) -> dict:
        """Fetching the schema from the ledger."""

        address = self.web3.to_checksum_address(
            self.ledgerConfig.contractAddrs[SCHEMA_REGISTRY]
        )
        contract = self.web3.eth.contract(
            address=address, abi=self.ledgerConfig.contractAbis[SCHEMA_REGISTRY]
        )
        schema = None
        try:
            schema_result = contract.functions.resolveSchema(schema_id).call()
            schema = {
                "ver": "1.0",
                "id": schema_result[0],
                "issuerId": schema_result[1],
                "name": schema_result[2],
                "version": schema_result[3],
                "attrNames": schema_result[4],
                "seqNo": "besu",
            }

            if self.cache:
                await self.cache.set(
                    f"schema::{schema_id}",
                    schema,
                    self.cache_duration,
                )

        except Exception as ex:
            raise LedgerError(f"Could not retrieve schema {schema_id}.") from ex
        return schema

    async def fetch_schema_by_seq_no(self, seq_no: int) -> dict:
        """Cant get schema by seqno in besu."""
        LOGGER.error("SeqNo not available on Besu VDR")
        raise NotImplementedError

    def credential_definition_id2schema_id(self, cred_def_id: str) -> str:
        """Get schema id. Just regex, no need to search the ledger for this."""

        schema_id = cred_def_id.split("CLAIM_DEF/")[1].split("/")
        schema_id.pop()
        schema_id = "/".join(schema_id)
        return schema_id

    async def get_credential_definition(self, credential_definition_id: str) -> dict:
        """Get a credential definition from the cache if available, otherwise the ledger.

        Args:
            credential_definition_id: The schema id of the schema to fetch cred def for

        """
        if self.pool.cache:
            cache_key = f"credential_definition::{credential_definition_id}"
            async with self.pool.cache.acquire(cache_key) as entry:
                if entry.result:
                    result = entry.result
                else:
                    result = await self.fetch_credential_definition(
                        credential_definition_id
                    )
                    if result:
                        await entry.set_result(result, self.pool.cache_duration)
                return result

        return await self.fetch_credential_definition(credential_definition_id)

    async def fetch_credential_definition(self, credential_definition_id: str) -> dict:
        """Get a credential definition from the ledger by id.

        Args:
            credential_definition_id: The cred def id of the cred def to fetch

        """

        # TODO: use public did
        address = self.web3.to_checksum_address(
            self.ledgerConfig.contractAddrs[CREDENTIAL_DEFINITION_REGISTRY]
        )
        contract = self.web3.eth.contract(
            address=address,
            abi=self.ledgerConfig.contractAddrs[CREDENTIAL_DEFINITION_REGISTRY],
        )

        cred_def = contract.functions.resolveCredentialDefinition(
            credential_definition_id
        ).call()

        if not len(cred_def):
            raise LedgerError(
                f"Credential definition not found: {credential_definition_id}",
                {"ledger_id": "Besu"},
            )

        cred_def = cred_def[0]
        result = {
            "id": cred_def[0],
            "issuerId": cred_def[1],
            "schemaId": cred_def[2],
            "type": cred_def[3],
            "tag": cred_def[4],
            "value": cred_def[5].replace("'", '"'),
        }

        return result

    async def get_revoc_reg_def(self, revoc_reg_id: str) -> dict:
        """Get the revocation registry definition."""
        address = self.web3.to_checksum_address(
            self.ledgerConfig.contractAddrs[REVOCATION_REGISTRY]
        )
        contract = self.web3.eth.contract(
            address=address, abi=self.ledgerConfig.contractAbis[REVOCATION_REGISTRY]
        )
        resolveResult = contract.functions.resolveRevocation(revoc_reg_id).call()
        LOGGER.debug(f"Receive rev_reg {resolveResult}")
        if len(resolveResult):

            revocationReg = resolveResult[0]

            result = {
                "ver": revocationReg[0],
                "id": revocationReg[1],
                "revocDefType": revocationReg[2],
                "credDefId": revocationReg[3],
                "tag": revocationReg[4],
                "value": json.loads(revocationReg[5]),
                "issuerId": revocationReg[6],
            }

            return result

        return None

    async def get_revoc_reg_delta(
        self, revoc_reg_id: str, timestamp_from=0, timestamp_to=None
    ) -> Tuple[dict, int]:
        """Get revocation delta."""
        address = self.web3.to_checksum_address(
            self.ledgerConfig.contractAddrs[REVOCATION_REGISTRY]
        )
        contract = self.web3.eth.contract(
            address=address, abi=self.ledgerConfig.contractAbis[REVOCATION_REGISTRY]
        )
        delta = contract.functions.resolveEntry(revoc_reg_id).call()
        LOGGER.debug(f"Received delta: {delta}")
        timestamp = delta[1][2]
        delta = json.loads(delta[0][2])
        if delta is None:
            raise LedgerError(
                f"Revocation list not found for rev reg def: {revoc_reg_id}",
                {"ledger_id": "Besu"},
            )
        LOGGER.debug("Retrieved delta: %s", delta)
        return delta, timestamp

    async def send_schema_anoncreds(
        self,
        schema_id: str,
        schema_def: dict,
        write_ledger: bool = True,
        endorser_did: str = None,
    ) -> Tuple[str, dict]:
        """Send schema to ledger. (Override from BaseLedger).

        Args:
            issuer: The issuer instance to use for schema creation
            schema_name: The schema name
            schema_version: The schema version
            attribute_names: A list of schema attributes

        """
        # TODO: public_did
        schema_info = await self.check_existing_schema_anoncreds(
            schema_id, schema_def["attrNames"]
        )
        if schema_info:
            LOGGER.warning("Schema already exists on ledger.")
            raise LedgerObjectAlreadyExistsError(
                "Schema already exists on ledger.", *schema_info
            )
        address = self.web3.to_checksum_address(
            self.ledgerConfig.contractAddrs[SCHEMA_REGISTRY]
        )
        contract = self.web3.eth.contract(
            address=address, abi=self.ledgerConfig.contractAbis[SCHEMA_REGISTRY]
        )
        call_function = contract.functions.createSchema(schema_def)
        tx_receipt = self._send_signed_transaction(call_function)

        LOGGER.debug("Receipt: %s", tx_receipt)

        return schema_id

    async def send_credential_definition_anoncreds(
        self,
        schema_id: str,
        cred_def_id: str,
        cred_def: dict,
        write_ledger: bool = True,
        endorser_did: str = None,
    ) -> Tuple[str, dict, bool]:
        """Send credential definition to ledger and store relevant key matter in wallet.

        Args:
            issuer: The issuer instance to use for credential definition creation
            schema_id: The schema id of the schema to create cred def for
            signature_type: The signature type to use on the credential definition
            tag: Optional tag to distinguish multiple credential definitions
            support_revocation: Optional flag to enable revocation for this cred def

        Returns:
            Tuple with cred def id, cred def structure, and whether it's novel

        """

        schema = await self.get_schema(schema_id)
        if not schema:
            raise LedgerError(f"Ledger has no schema {schema_id}")

        # check if cred def is on ledger already
        ledger_cred_def = await self.fetch_credential_definition(cred_def_id)
        if ledger_cred_def:
            credential_definition_json = json.dumps(ledger_cred_def)
            raise LedgerObjectAlreadyExistsError(
                f"Credential definition with id {cred_def_id} "
                "already exists in wallet and on ledger.",
                cred_def_id,
                credential_definition_json,
            )

        if self.is_ledger_read_only():
            raise LedgerError(
                "Error cannot write cred def when ledger is in read only mode"
            )

        address = self.web3.to_checksum_address(
            self.ledgerConfig.contractAddrs[CREDENTIAL_DEFINITION_REGISTRY]
        )
        contract = self.web3.eth.contract(
            address=address,
            abi=self.ledgerConfig.contractAbis[CREDENTIAL_DEFINITION_REGISTRY],
        )
        call_function = contract.functions.createCredentialDefinition(cred_def)
        tx_receipt = self._send_signed_transaction(call_function)
        LOGGER.debug("Receipt: %s", tx_receipt)

        result = self.fetch_credential_definition(cred_def_id)
        if not result:
            raise LedgerError("Failed to register credef")

        return "besu"

    def _send_signed_transaction(self, contractFunction: ContractFunction) -> TxReceipt:
        nonce = self.web3.eth.get_transaction_count(self.ledgerConfig.trusteeAccount)
        chain_id = self.web3.eth.chain_id
        tx = contractFunction.build_transaction(
            {
                "chainId": chain_id,
                "from": self.ledgerConfig.trusteeAccount,
                "nonce": nonce,
                "gas": 3000000,
            }
        )
        # Sign transaction
        signed_tx = self.web3.eth.account.sign_transaction(
            tx, private_key=self.ledgerConfig.trusteePKey
        )

        # Send transaction
        LOGGER.debug("Transaction: %s", signed_tx.rawTransaction)
        send_tx = self.web3.eth.send_raw_transaction(signed_tx.rawTransaction)

        # Wait for transaction receipt
        tx_receipt = self.web3.eth.wait_for_transaction_receipt(send_tx)

        return tx_receipt

    async def get_key_for_did(self, did: str) -> str:
        """Get key for did."""
        LOGGER.info(f"Getting key for did {did}")
        raise NotImplementedError

    async def get_endpoint_for_did(
        self, did: str, endpoint_type: EndpointType = EndpointType.ENDPOINT
    ) -> str:
        raise NotImplementedError

    async def get_all_endpoints_for_did(self, did: str) -> dict:
        raise NotImplementedError

    async def update_endpoint_for_did(
        self,
        did: str,
        endpoint: str,
        endpoint_type: EndpointType = EndpointType.ENDPOINT,
        write_ledger: bool = True,
        endorser_did: str = None,
        routing_keys: List[str] = None,
    ) -> bool:
        LOGGER.info(
            f"Trying to update did {did} setting endpoint to {endpoint}. That's not "
            "implemented yet"
        )

    async def register_nym(
        self,
        did: str,
        verkey: str,
        alias: str = None,
        role: str = None,
        write_ledger: bool = True,
        endorser_did: str = None,
    ) -> Tuple[bool, dict]:
        raise NotImplementedError

    async def get_nym_role(self, did: str):
        raise NotImplementedError

    def nym_to_did(self, nym: str) -> str:
        raise NotImplementedError

    async def rotate_public_did_keypair(self, next_seed: str = None) -> None:
        raise NotImplementedError

    async def get_wallet_public_did(self) -> DIDInfo:
        """Fetch the public DID from the wallet."""
        async with self.profile.session() as session:
            wallet = session.inject(BaseWallet)
            return await wallet.get_public_did()

    async def _create_revoc_reg_def_request(
        self,
        public_info: DIDInfo,
        revoc_reg_def: dict,
        write_ledger: bool = True,
        endorser_did: str = None,
    ):
        raise NotImplementedError

    async def send_revoc_reg_def(
        self,
        revoc_reg_def: dict,
        issuer_did: str = None,
        write_ledger: bool = True,
        endorser_did: str = None,
    ) -> dict:
        raise NotImplementedError

    async def send_revoc_reg_entry(
        self,
        revoc_reg_id: str,
        revoc_def_type: str,
        revoc_reg_entry: dict,
        issuer_did: str = None,
        write_ledger: bool = True,
        endorser_did: str = None,
    ) -> dict:
        raise NotImplementedError

    async def _create_credential_definition_request(
        self,
        public_info: DIDInfo,
        credential_definition_json: str,
        write_ledger: bool = True,
        endorser_did: str = None,
    ):
        raise NotImplementedError

    async def _create_schema_request(
        self,
        public_info: DIDInfo,
        schema_json: str,
        write_ledger: bool = True,
        endorser_did: str = None,
    ):
        """Wont need it."""
        raise NotImplementedError

    async def get_revoc_reg_entry(
        self, revoc_reg_id: str, timestamp: int
    ) -> Tuple[dict, int]:
        """Not used for anoncreds."""
        raise NotImplementedError

    async def get_txn_author_agreement(self, reload: bool = False):
        """Wont be used."""
        return {"taa_required": False}

    async def fetch_txn_author_agreement(self):
        """Wont be used."""
        raise NotImplementedError

    async def accept_txn_author_agreement(
        self, taa_record: dict, mechanism: str, accept_time: int = None
    ):
        """Wont be used."""
        raise NotImplementedError

    async def get_latest_txn_author_acceptance(self):
        """Wont be used."""
        raise NotImplementedError

    async def txn_endorse(self, request_json: str, endorse_did: DIDInfo = None) -> str:
        """Wont be used."""
        raise NotImplementedError

    async def txn_submit(
        self,
        request_json: str,
        sign: bool,
        taa_accept: bool = None,
        sign_did: DIDInfo = ...,
        write_ledger: bool = True,
    ) -> str:
        """Wont be used."""
        raise NotImplementedError

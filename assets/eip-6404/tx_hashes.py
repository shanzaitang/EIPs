from rlp_types import *
from ssz_types import *

def recover_legacy_rlp_transaction(
        tx: RlpLegacyTransaction) -> LegacyRlpTransaction:
    y_parity, r, s = secp256k1_unpack_signature(tx.from_.secp256k1_signature)
    if tx.payload.chain_id is not None:  # EIP-155
        v = uint256(1 if y_parity else 0) + 35 + tx.payload.chain_id * 2
    else:
        v = uint256(1 if y_parity else 0) + 27

    return LegacyRlpTransaction(
        nonce=tx.payload.nonce,
        gas_price=tx.payload.max_fees_per_gas.regular,
        gas=tx.payload.gas,
        to=bytes(tx.payload.to if tx.payload.to is not None else []),
        value=tx.payload.value,
        data=tx.payload.input_,
        v=v,
        r=r,
        s=s,
    )

def recover_access_list_rlp_transaction(
        tx: RlpAccessListTransaction) -> AccessListRlpTransaction:
    y_parity, r, s = secp256k1_unpack_signature(tx.from_.secp256k1_signature)

    return AccessListRlpTransaction(
        chain_id=tx.payload.chain_id,
        nonce=tx.payload.nonce,
        gas_price=tx.payload.max_fees_per_gas.regular,
        gas=tx.payload.gas,
        to=bytes(tx.payload.to if tx.payload.to is not None else []),
        value=tx.payload.value,
        data=tx.payload.input_,
        access_list=[(
            access_tuple.address,
            access_tuple.storage_keys,
        ) for access_tuple in tx.payload.access_list],
        y_parity=1 if y_parity else 0,
        r=r,
        s=s,
    )

def recover_fee_market_rlp_transaction(
        tx: RlpFeeMarketTransaction) -> FeeMarketRlpTransaction:
    y_parity, r, s = secp256k1_unpack_signature(tx.from_.secp256k1_signature)

    return FeeMarketRlpTransaction(
        chain_id=tx.payload.chain_id,
        nonce=tx.payload.nonce,
        max_priority_fee_per_gas=tx.payload.max_priority_fees_per_gas.regular,
        max_fee_per_gas=tx.payload.max_fees_per_gas.regular,
        gas=tx.payload.gas,
        to=bytes(tx.payload.to if tx.payload.to is not None else []),
        value=tx.payload.value,
        data=tx.payload.input_,
        access_list=[(
            access_tuple.address,
            access_tuple.storage_keys,
        ) for access_tuple in tx.payload.access_list],
        y_parity=1 if y_parity else 0,
        r=r,
        s=s,
    )

def recover_blob_rlp_transaction(tx: RlpBlobTransaction) -> BlobRlpTransaction:
    assert tx.payload.max_priority_fees_per_gas.blob == FeePerGas(0)
    y_parity, r, s = secp256k1_unpack_signature(tx.from_.secp256k1_signature)

    return BlobRlpTransaction(
        chain_id=tx.payload.chain_id,
        nonce=tx.payload.nonce,
        max_priority_fee_per_gas=tx.payload.max_priority_fees_per_gas.regular,
        max_fee_per_gas=tx.payload.max_fees_per_gas.regular,
        gas=tx.payload.gas,
        to=tx.payload.to,
        value=tx.payload.value,
        data=tx.payload.input_,
        access_list=[(
            access_tuple.address,
            access_tuple.storage_keys,
        ) for access_tuple in tx.payload.access_list],
        max_fee_per_blob_gas=tx.payload.max_fees_per_gas.blob,
        blob_versioned_hashes=tx.payload.blob_versioned_hashes,
        y_parity=1 if y_parity else 0,
        r=r,
        s=s,
    )

def recover_set_code_rlp_authorization(
        auth: RlpSetCodeAuthorization) -> SetCodeRlpAuthorization:
    assert auth.payload.magic == 0x05
    assert auth.payload.chain_id != 0
    y_parity, r, s = secp256k1_unpack_signature(
        auth.authority.secp256k1_signature)

    return SetCodeRlpAuthorization(
        chain_id=auth.payload.chain_id if auth.payload.chain_id is not None else 0,
        address=auth.payload.address,
        nonce=auth.payload.nonce,
        y_parity=1 if y_parity else 0,
        r=r,
        s=s,
    )

def recover_set_code_rlp_transaction(
        tx: RlpSetCodeTransaction) -> SetCodeRlpTransaction:
    y_parity, r, s = secp256k1_unpack_signature(tx.from_.secp256k1_signature)

    return SetCodeRlpTransaction(
        chain_id=tx.payload.chain_id,
        nonce=tx.payload.nonce,
        max_priority_fee_per_gas=tx.payload.max_priority_fees_per_gas.regular,
        max_fee_per_gas=tx.payload.max_fees_per_gas.regular,
        gas=tx.payload.gas,
        to=tx.payload.to,
        value=tx.payload.value,
        data=tx.payload.input_,
        access_list=[(
            access_tuple.address,
            access_tuple.storage_keys,
        ) for access_tuple in tx.payload.access_list],
        authorization_list=[
            recover_set_code_rlp_authorization(auth)
            for auth in tx.payload.authorization_list
        ],
        y_parity=1 if y_parity else 0,
        r=r,
        s=s,
    )

def compute_sig_hash(tx) -> Hash32:
    if isinstance(tx, RlpSetCodeTransaction):
        pre = recover_set_code_rlp_transaction(tx)
        return compute_set_code_sig_hash(pre)

    if isinstance(tx, RlpBlobTransaction):
        pre = recover_blob_rlp_transaction(tx)
        return compute_blob_sig_hash(pre)

    if isinstance(tx, RlpFeeMarketTransaction):
        pre = recover_fee_market_rlp_transaction(tx)
        return compute_fee_market_sig_hash(pre)

    if isinstance(tx, RlpAccessListTransaction):
        pre = recover_access_list_rlp_transaction(tx)
        return compute_access_list_sig_hash(pre)

    if isinstance(tx, RlpLegacyTransaction):
        pre = recover_legacy_rlp_transaction(tx)
        return compute_legacy_sig_hash(pre)

    raise Exception(f'Unsupported transaction: {tx}')

def compute_tx_hash(tx) -> Hash32:
    if isinstance(tx, RlpSetCodeTransaction):
        pre = recover_set_code_rlp_transaction(tx)
        return compute_set_code_tx_hash(pre)

    if isinstance(tx, RlpBlobTransaction):
        pre = recover_blob_rlp_transaction(tx)
        return compute_blob_tx_hash(pre)

    if isinstance(tx, RlpFeeMarketTransaction):
        pre = recover_fee_market_rlp_transaction(tx)
        return compute_fee_market_tx_hash(pre)

    if isinstance(tx, RlpAccessListTransaction):
        pre = recover_access_list_rlp_transaction(tx)
        return compute_access_list_tx_hash(pre)

    if isinstance(tx, RlpLegacyTransaction):
        pre = recover_legacy_rlp_transaction(tx)
        return compute_legacy_tx_hash(pre)

    raise Exception(f'Unsupported transaction: {tx}')

def compute_auth_hash(auth) -> Hash32:
    if isinstance(auth, RlpSetCodeAuthorization):
        pre = recover_set_code_rlp_authorization(auth)
        return compute_set_code_auth_hash(pre)

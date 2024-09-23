from rlp import decode
from rlp_types import *
from ssz_types import *

def upgrade_rlp_transaction_to_ssz(pre_bytes: bytes):
    type_ = pre_bytes[0]

    if type_ == 0x04:  # EIP-7702
        pre = decode(pre_bytes[1:], SetCodeRlpTransaction)

        authorization_list = List[Authorization, MAX_AUTHORIZATION_LIST_SIZE]()
        for auth in pre.authorization_list:
            assert auth.y_parity in (0, 1)
            secp256k1_signature = secp256k1_pack_signature(
                auth.y_parity != 0, auth.r, auth.s)
            authority_address = secp256k1_recover_signer_address(
                secp256k1_signature, compute_set_code_auth_hash(auth))

            authorization_list.append(Authorization(backing=RlpSetCodeAuthorization(
                payload=RlpSetCodeAuthorizationPayload(
                    magic=SET_CODE_TX_MAGIC,
                    chain_id=auth.chain_id if auth.chain_id != 0 else None,
                    address=ExecutionAddress(auth.address),
                    nonce=auth.nonce,
                ),
                authority=Secp256k1ExecutionSignature(
                    address=authority_address,
                    secp256k1_signature=secp256k1_signature,
                ),
            ).get_backing()))

        assert pre.y_parity in (0, 1)
        secp256k1_signature = secp256k1_pack_signature(
            pre.y_parity != 0, pre.r, pre.s)
        from_address = secp256k1_recover_signer_address(
            secp256k1_signature, compute_set_code_sig_hash(pre))

        return RlpSetCodeTransaction(
            payload=RlpSetCodeTransactionPayload(
                type_=SET_CODE_TX_TYPE,
                chain_id=pre.chain_id,
                nonce=pre.nonce,
                max_fees_per_gas=BlobFeesPerGas(
                    regular=pre.max_fee_per_gas,
                ),
                gas=pre.gas,
                to=ExecutionAddress(pre.to),
                value=pre.value,
                input_=pre.data,
                access_list=[AccessTuple(
                    address=access_tuple[0],
                    storage_keys=access_tuple[1]
                ) for access_tuple in pre.access_list],
                max_priority_fees_per_gas=BlobFeesPerGas(
                    regular=pre.max_priority_fee_per_gas,
                ),
                authorization_list=authorization_list,
            ),
            from_=Secp256k1ExecutionSignature(
                address=from_address,
                secp256k1_signature=secp256k1_signature,
            ),
        )

    if type_ == 0x03:  # EIP-4844
        pre = decode(pre_bytes[1:], BlobRlpTransaction)
        assert pre.y_parity in (0, 1)
        secp256k1_signature = secp256k1_pack_signature(
            pre.y_parity != 0,
            pre.r,
            pre.s,
        )
        from_address = secp256k1_recover_signer_address(
            secp256k1_signature, compute_blob_sig_hash(pre))

        return RlpBlobTransaction(
            payload=RlpBlobTransactionPayload(
                type_=BLOB_TX_TYPE,
                chain_id=pre.chain_id,
                nonce=pre.nonce,
                max_fees_per_gas=BlobFeesPerGas(
                    regular=pre.max_fee_per_gas,
                    blob=pre.max_fee_per_blob_gas,
                ),
                gas=pre.gas,
                to=ExecutionAddress(pre.to),
                value=pre.value,
                input_=pre.data,
                access_list=[AccessTuple(
                    address=access_tuple[0],
                    storage_keys=access_tuple[1]
                ) for access_tuple in pre.access_list],
                max_priority_fees_per_gas=BlobFeesPerGas(
                    regular=pre.max_priority_fee_per_gas,
                    blob=FeePerGas(0),
                ),
                blob_versioned_hashes=pre.blob_versioned_hashes,
            ),
            from_=Secp256k1ExecutionSignature(
                address=from_address,
                secp256k1_signature=secp256k1_signature,
            ),
        )

    if type_ == 0x02:  # EIP-1559
        pre = decode(pre_bytes[1:], FeeMarketRlpTransaction)
        assert pre.y_parity in (0, 1)
        secp256k1_signature = secp256k1_pack_signature(
            pre.y_parity != 0, pre.r, pre.s)
        from_address = secp256k1_recover_signer_address(
            secp256k1_signature, compute_fee_market_sig_hash(pre))

        return RlpFeeMarketTransaction(
            payload=RlpFeeMarketTransactionPayload(
                type_=FEE_MARKET_TX_TYPE,
                chain_id=pre.chain_id,
                nonce=pre.nonce,
                max_fees_per_gas=BasicFeesPerGas(
                    regular=pre.max_fee_per_gas,
                ),
                gas=pre.gas,
                to=ExecutionAddress(pre.to) if len(pre.to) > 0 else None,
                value=pre.value,
                input_=pre.data,
                access_list=[AccessTuple(
                    address=access_tuple[0],
                    storage_keys=access_tuple[1]
                ) for access_tuple in pre.access_list],
                max_priority_fees_per_gas=BasicFeesPerGas(
                    regular=pre.max_priority_fee_per_gas,
                ),
            ),
            from_=Secp256k1ExecutionSignature(
                address=from_address,
                secp256k1_signature=secp256k1_signature,
            ),
        )

    if type_ == 0x01:  # EIP-2930
        pre = decode(pre_bytes[1:], AccessListRlpTransaction)
        assert pre.y_parity in (0, 1)
        secp256k1_signature = secp256k1_pack_signature(
            pre.y_parity != 0, pre.r, pre.s)
        from_address = secp256k1_recover_signer_address(
            secp256k1_signature, compute_access_list_sig_hash(pre))

        return RlpAccessListTransaction(
            payload=RlpAccessListTransactionPayload(
                type_=ACCESS_LIST_TX_TYPE,
                chain_id=pre.chain_id,
                nonce=pre.nonce,
                max_fees_per_gas=BasicFeesPerGas(
                    regular=pre.gas_price,
                ),
                gas=pre.gas,
                to=ExecutionAddress(pre.to) if len(pre.to) > 0 else None,
                value=pre.value,
                input_=pre.data,
                access_list=[AccessTuple(
                    address=access_tuple[0],
                    storage_keys=access_tuple[1]
                ) for access_tuple in pre.access_list],
            ),
            from_=Secp256k1ExecutionSignature(
                address=from_address,
                secp256k1_signature=secp256k1_signature,
            ),
        )

    if 0xc0 <= type_ <= 0xfe:  # Legacy
        pre = decode(pre_bytes, LegacyRlpTransaction)
        secp256k1_signature = secp256k1_pack_signature(
            (pre.v & 0x1) == 0, pre.r, pre.s)
        from_address = secp256k1_recover_signer_address(
            secp256k1_signature, compute_legacy_sig_hash(pre))

        if (pre.v not in (27, 28)):  # EIP-155
            chain_id = ((pre.v - 35) >> 1)
        else:
            chain_id = None

        return RlpLegacyTransaction(
            payload=RlpLegacyTransactionPayload(
                type_=LEGACY_TX_TYPE,
                chain_id=chain_id,
                nonce=pre.nonce,
                max_fees_per_gas=BasicFeesPerGas(
                    regular=pre.gas_price,
                ),
                gas=pre.gas,
                to=ExecutionAddress(pre.to) if len(pre.to) > 0 else None,
                value=pre.value,
                input_=pre.data,
            ),
            from_=Secp256k1ExecutionSignature(
                address=from_address,
                secp256k1_signature=secp256k1_signature,
            ),
        )

    assert False

"""Exact-flowchart authenticated 32x32 block-TPE prototype.

Order: legacy block-preserving TPE/RDH -> reversible pair Step-1 -> reversible
pair Step-2 -> HMAC-SHA256 over the post-Step-2 four-block group -> HMAC_DRBG
block grouping -> reversible contrast-mapping (RCM) tag embedding.

Capacity repair: within each 32x32 block, a stable value-sorted *logical pair
layout* pairs nearby ciphertext values before Step-1/Step-2/RCM. A reversible
block-sum correction then restores every 32x32 channel sum to the source value.
The pairing map, correction vector and both schedule identifiers are carried in
a ChaCha20-Poly1305-protected sidecar; the pairing map is also included in each
group MAC. The TPE-native RDH tags and caller payload stay in the image stream.
No whole-image fallback is used: encryption fails closed if any four-block
group lacks capacity.
"""
from __future__ import annotations
from dataclasses import dataclass
import hashlib, hmac, secrets, zlib
import struct
from typing import Sequence
import numpy as np
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
import block32_authenticated_tpe as common

BLOCK=32
GROUP=4
TAG_BYTES=32
TAG_BITS=256
_DOMAIN=b"authenticated-tpe:flowchart-exact:v2\x00"
_SIDECAR_MAGIC=b"ATPE"
_SIDECAR_VERSION=1
_SIDECAR_HEADER=struct.Struct(">4sBBHII16s12s")

@dataclass(frozen=True)
class ExactEncryption:
    marked_image: np.ndarray
    layout_sidecar: bytes
    auth_image_id: bytes
    tpe_image_identifier: object
    group_count: int
    minimum_group_capacity: int
    group_capacities: tuple[int, ...]
    rdh_infos: tuple = ()

@dataclass(frozen=True)
class ExactVerification:
    accepted: bool
    reason: str
    restored_tpe_ciphertext: np.ndarray | None
    failed_groups: tuple[tuple[int, int], ...]
    layout: np.ndarray | None = None
    recovered_payload_bits: list[int] | None = None
    tpe_image_identifier: object | None = None
    auth_image_id: bytes | None = None

@dataclass(frozen=True)
class ExactDecryption:
    accepted: bool
    reason: str
    recovered_image: np.ndarray | None
    recovered_payload_bits: list[int] | None
    failed_groups: tuple[tuple[int, int], ...]


def _dimensions(a: np.ndarray) -> tuple[int,int,int]:
    h,w,n=common._dimensions(np.asarray(a))
    return h,w,n


def _layout_from_ciphertext(a: np.ndarray) -> np.ndarray:
    """Stable ascending value rank for each channel/block; indices are 0..1023."""
    _,_,nblocks=_dimensions(a)
    layout=np.empty((3,nblocks,BLOCK*BLOCK),dtype=np.uint16)
    for c in range(3):
        for bid in range(nblocks):
            values=common._block(a,c,bid).reshape(-1).copy()
            layout[c,bid]=np.argsort(values,kind="stable").astype(np.uint16)
    return layout


def _validate_layout(layout: np.ndarray, nblocks: int) -> np.ndarray:
    a=np.asarray(layout)
    if a.shape!=(3,nblocks,BLOCK*BLOCK) or a.dtype!=np.uint16:
        raise ValueError("layout has an invalid shape or dtype")
    expected=np.arange(BLOCK*BLOCK,dtype=np.uint16)
    for c in range(3):
        for bid in range(nblocks):
            if not np.array_equal(np.sort(a[c,bid]),expected):
                raise ValueError("layout contains a non-permutation block")
    return np.ascontiguousarray(a)


def _pack(a: np.ndarray, layout: np.ndarray) -> np.ndarray:
    """Gather each block's pixels in logical sorted-rank order."""
    out=np.empty_like(a)
    for c in range(3):
        for bid in range(layout.shape[1]):
            src=common._block(a,c,bid).reshape(-1)
            common._block(out,c,bid)[:]=src[layout[c,bid]].reshape(BLOCK,BLOCK)
    return out


def _scatter(packed: np.ndarray, layout: np.ndarray) -> np.ndarray:
    """Restore logical-rank pixels to their original block coordinates."""
    out=np.empty_like(packed)
    for c in range(3):
        for bid in range(layout.shape[1]):
            logical=common._block(packed,c,bid).reshape(-1)
            physical=np.empty(BLOCK*BLOCK,dtype=np.uint8)
            physical[layout[c,bid]]=logical
            common._block(out,c,bid)[:]=physical.reshape(BLOCK,BLOCK)
    return out


def _aad(image_id: bytes, h: int, w: int) -> bytes:
    return _DOMAIN+b"layout-aead\x00"+image_id+h.to_bytes(4,"big")+w.to_bytes(4,"big")


def _layout_key(user_key: bytes) -> bytes:
    kauth=common.auth_primitives.derive_keys(bytes(user_key))["Kauth"]
    return hmac.new(kauth,b"authenticated-tpe:layout-sidecar:v2",hashlib.sha256).digest()


def _encode_identifier(identifier: object) -> bytes:
    if isinstance(identifier, str):
        kind, value = b"s", identifier.encode("utf-8")
    elif isinstance(identifier, int):
        if identifier < 0:
            raise ValueError("TPE image identifier integer must be non-negative")
        kind = b"i"
        value = identifier.to_bytes(max(1, (identifier.bit_length() + 7) // 8), "big")
    elif isinstance(identifier, (bytes, bytearray)):
        kind, value = b"b", bytes(identifier)
    else:
        raise TypeError("unsupported TPE image identifier type")
    if len(value) > 0xFFFF:
        raise ValueError("TPE image identifier is too long for the sidecar format")
    return kind + len(value).to_bytes(2, "big") + value


def _decode_identifier(data: bytes) -> object:
    if len(data) < 3:
        raise ValueError("TPE image identifier metadata is truncated")
    kind, length = data[:1], int.from_bytes(data[1:3], "big")
    value = data[3:]
    if len(value) != length:
        raise ValueError("TPE image identifier length is invalid")
    if kind == b"s":
        return value.decode("utf-8")
    if kind == b"b":
        if not value:
            raise ValueError("TPE image identifier must not be empty")
        return value
    if kind == b"i":
        return int.from_bytes(value, "big")
    raise ValueError("TPE image identifier type is invalid")


def _seal_layout(layout: np.ndarray, correction: np.ndarray, user_key: bytes,
                 image_id: bytes, h: int, w: int, tpe_identifier: object,
                 payload_bits: Sequence[int] = ()) -> bytes:
    raw=(np.asarray(layout,dtype=">u2").tobytes(order="C")+
         np.asarray(correction,dtype=">i2").tobytes(order="C")+
         _encode_identifier(tpe_identifier)+
         len(payload_bits).to_bytes(8,"big")+bytes(int(bit) for bit in payload_bits))
    compressed=zlib.compress(raw,level=9)
    image_id=bytes(image_id)
    if len(image_id)!=16:
        raise ValueError("ImageID must be exactly 16 bytes")
    if not (0 < h <= 0xFFFFFFFF and 0 < w <= 0xFFFFFFFF):
        raise ValueError("image dimensions are outside the sidecar format range")
    nonce=secrets.token_bytes(12)
    # The fixed header is public and authenticated as AEAD associated data.
    # Recovery maps, the TPE schedule identifier and optional sidecar payload
    # remain encrypted in `compressed`.
    header=_SIDECAR_HEADER.pack(_SIDECAR_MAGIC,_SIDECAR_VERSION,0,0,h,w,image_id,nonce)
    ciphertext=ChaCha20Poly1305(_layout_key(user_key)).encrypt(nonce,compressed,header)
    return header+ciphertext


def _open_layout(blob: bytes, user_key: bytes, image_id: bytes, h: int, w: int,
                 nblocks: int) -> tuple[np.ndarray,np.ndarray,list[int],object,bytes]:
    if len(blob)<_SIDECAR_HEADER.size+16:
        raise ValueError("layout sidecar is missing or malformed")
    magic,version,flags,reserved,stored_h,stored_w,stored_image_id,nonce=(
        _SIDECAR_HEADER.unpack(blob[:_SIDECAR_HEADER.size]))
    if magic!=_SIDECAR_MAGIC or version!=_SIDECAR_VERSION or flags or reserved:
        raise ValueError("unsupported or malformed sidecar header")
    if (stored_h,stored_w)!=(h,w):
        raise ValueError("sidecar dimensions do not match the image")
    if image_id is not None and not hmac.compare_digest(bytes(image_id),stored_image_id):
        raise ValueError("authentication ImageID does not match sidecar metadata")
    header=blob[:_SIDECAR_HEADER.size]
    ciphertext=blob[_SIDECAR_HEADER.size:]
    compressed=ChaCha20Poly1305(_layout_key(user_key)).decrypt(nonce,ciphertext,header)
    raw=zlib.decompress(compressed)
    plane=3*nblocks*BLOCK*BLOCK
    base=plane*4
    if len(raw)<base+3+8:
        raise ValueError("layout sidecar length does not match image dimensions")
    layout=np.frombuffer(raw[:plane*2],dtype=">u2").astype(np.uint16).reshape(3,nblocks,BLOCK*BLOCK)
    correction=np.frombuffer(raw[plane*2:base],dtype=">i2").astype(np.int16).reshape(3,nblocks,BLOCK*BLOCK)
    if np.any(correction < -255) or np.any(correction > 255):
        raise ValueError("block-sum correction is outside the uint8 range")
    identifier_length=int.from_bytes(raw[base+1:base+3],"big")
    identifier_end=base+3+identifier_length
    if identifier_end+8>len(raw):
        raise ValueError("TPE image identifier metadata is truncated")
    tpe_identifier=_decode_identifier(raw[base:identifier_end])
    expected=identifier_end+8
    payload_length=int.from_bytes(raw[identifier_end:expected],"big")
    if payload_length>len(raw)-expected or len(raw)!=expected+payload_length:
        raise ValueError("sidecar payload length is invalid")
    payload_bytes=raw[expected:]
    if any(bit not in (0,1) for bit in payload_bytes):
        raise ValueError("sidecar payload contains a non-binary value")
    return _validate_layout(layout,nblocks),correction,list(payload_bytes),tpe_identifier,stored_image_id


def _balanced_adjust(values: np.ndarray, delta: int) -> np.ndarray:
    """Find a deterministic low-spread uint8 adjustment whose sum is delta."""
    values=np.asarray(values,dtype=np.int64).reshape(-1)
    adjust=np.zeros(values.size,dtype=np.int16)
    remaining=int(delta)
    sign=1 if remaining>=0 else -1
    while remaining:
        current=values.astype(np.int64)+adjust.astype(np.int64)
        room=(255-current) if sign>0 else current
        active=np.flatnonzero(room>0)
        if not active.size:
            raise ValueError("cannot restore target block sum within uint8 bounds")
        amount=abs(remaining)
        share,remainder=divmod(amount,int(active.size))
        if share==0:
            adjust[active[:remainder]]+=sign
            remaining=0
            continue
        increments=np.minimum(room[active],share)
        applied=int(increments.sum())
        adjust[active]+=sign*increments.astype(np.int16)
        remaining-=sign*applied
    return adjust


def _restore_block_sums(marked: np.ndarray, target: np.ndarray) -> np.ndarray:
    """Apply a reversible, per-block correction and return its signed map."""
    _,_,nblocks=_dimensions(marked)
    correction=np.empty((3,nblocks,BLOCK*BLOCK),dtype=np.int16)
    for c in range(3):
        for bid in range(nblocks):
            values=common._block(marked,c,bid).reshape(-1).astype(np.int64)
            target_sum=int(common._block(target,c,bid).sum(dtype=np.int64))
            delta=target_sum-int(values.sum())
            adj=_balanced_adjust(values,delta)
            corrected=values+adj.astype(np.int64)
            if int(corrected.sum())!=target_sum or corrected.min()<0 or corrected.max()>255:
                raise AssertionError("block-sum correction failed its invariant")
            correction[c,bid]=adj
            common._block(marked,c,bid)[:]=corrected.astype(np.uint8).reshape(BLOCK,BLOCK)
    return correction


def _undo_block_sum_correction(packed: np.ndarray, correction: np.ndarray) -> tuple[np.ndarray,tuple[tuple[int,int],...]]:
    out=np.empty_like(packed)
    invalid=[]
    for c in range(3):
        for bid in range(correction.shape[1]):
            values=common._block(packed,c,bid).astype(np.int32)
            restored=values-correction[c,bid].astype(np.int32).reshape(BLOCK,BLOCK)
            if restored.min()<0 or restored.max()>255:
                invalid.append((c,bid))
                common._block(out,c,bid)[:]=common._block(packed,c,bid)
            else:
                common._block(out,c,bid)[:]=restored.astype(np.uint8)
    return out,tuple(invalid)


def _group_layout_bytes(layout: np.ndarray, c: int, ids: Sequence[int]) -> bytes:
    return b"".join(np.asarray(layout[c,bid],dtype=">u2").tobytes() for bid in ids)


def _tag(user_key: bytes, image_id: bytes, c: int, ids: Sequence[int],
         post_step2: np.ndarray, layout: np.ndarray) -> bytes:
    kauth=common.auth_primitives.derive_keys(user_key)["Kauth"]
    gkey=common.auth_primitives.derive_group_key(kauth,image_id,c,ids)
    msg=bytearray(_DOMAIN+image_id+bytes([c]))
    for bid in ids:
        msg+=int(bid).to_bytes(2,"big")
    # Tags bind the carrier in the flowchart's post-Step-2 state and the
    # encrypted layout metadata needed to interpret RCM pair locations.
    for bid in ids:
        msg+=common._block_bytes(post_step2,c,bid)
    msg+=_group_layout_bytes(layout,c,ids)
    return hmac.new(gkey,bytes(msg),hashlib.sha256).digest()


def _capacity(a: np.ndarray, c: int, ids: Sequence[int]) -> int:
    net=0
    for cc,bid,k in common._slots(c,ids):
        x,y=common._get_pair(a,cc,bid,k)
        net += -1 if common.auth_primitives.classify_pair(x,y)=="N" else 1
    return net


def encrypt_authenticated_tpe(image: np.ndarray, payload_bits: Sequence[int],
                              tpe_params: common.legacy.DemoPipelineParameters,
                              auth_key: bytes, auth_image_id: bytes | None = None,
                              tpe_module=None) -> ExactEncryption:
    # A dedicated research branch may inject another reversible TPE adapter;
    # the existing pipeline remains the unchanged default.
    tpe_module=common.legacy if tpe_module is None else tpe_module
    source=np.ascontiguousarray(image)
    h,w,nblocks=_dimensions(source)
    if tpe_params.block_size!=BLOCK:
        raise ValueError("exact-order prototype requires legacy block size 32")
    key=bytes(auth_key)
    if len(key)<16:
        raise ValueError("authentication key must be at least 128 bits")
    payload=tpe_module._validate_bits(payload_bits)
    iid=secrets.token_bytes(16) if auth_image_id is None else bytes(auth_image_id)
    if len(iid)!=16:
        raise ValueError("ImageID must be exactly 16 bytes")

    # Stage 1: selected reversible block TPE/RDH output.
    tpe_result=tpe_module.encrypt_rgb_image(source,payload,tpe_params)
    tpe_cipher=np.ascontiguousarray(tpe_result.encrypted_image)
    layout=_layout_from_ciphertext(tpe_cipher)
    packed=_pack(tpe_cipher,layout)

    # Stages 2–3: reversible authenticated pair transforms after the TPE output.
    step1=common._auth_step1(packed,key,iid)
    post_step2=common._auth_step2(step1,key)

    # Stage 4: establish the exact HMAC_DRBG four-block groups and fail closed
    # if any group cannot hold its complete 256-bit HMAC tag.
    groups_by_channel=[common._group_order(key,c,nblocks) for c in range(3)]
    capacities=[_capacity(post_step2,c,ids) for c in range(3) for ids in groups_by_channel[c]]
    if not capacities or min(capacities)<TAG_BITS:
        raise RuntimeError(f"insufficient RCM capacity for exact four-block authentication; minimum={min(capacities,default=-1)} bits")

    # Stage 5: HMAC-SHA256 tags are over the post-Step-2 image, then the tags
    # are inserted by reversible RCM. No whole-image fallback is permitted.
    marked=post_step2.copy()
    total=0
    for c,groups in enumerate(groups_by_channel):
        for ids in groups:
            tag=_tag(key,iid,c,ids,post_step2,layout)
            if not common._embed(marked,common._slots(c,ids),tag):
                raise AssertionError("capacity preflight disagreed with the RCM embedder")
            total+=1

    # Restore each displayed 32x32 RGB block sum to the original source.
    # The authenticated correction vector is undone before the TPE's native
    # RDH extraction, preserving both thumbnail identity and exact recovery.
    correction=_restore_block_sums(marked,source)
    layout_payload = payload if getattr(tpe_module, "SIDECAR_PAYLOAD", False) else ()
    layout_blob=_seal_layout(layout,correction,key,iid,h,w,tpe_result.image_identifier,layout_payload)
    final=_scatter(marked,layout)
    return ExactEncryption(final,layout_blob,iid,tpe_result.image_identifier,total,min(capacities),tuple(capacities),getattr(tpe_result,"rdh_infos",()))


def verify_tpe_ciphertext(marked_image: np.ndarray, layout_sidecar: bytes,
                          user_key: bytes, image_id: bytes | None = None) -> ExactVerification:
    src=np.ascontiguousarray(marked_image)
    try:
        h,w,nblocks=_dimensions(src)
        key=bytes(user_key)
        if len(key)<16:
            raise ValueError("invalid authentication key")
        layout,correction,payload_bits,tpe_identifier,iid=_open_layout(bytes(layout_sidecar),key,image_id,h,w,nblocks)
    except Exception as exc:
        return ExactVerification(False,f"layout/key validation failed: {type(exc).__name__}",None,())

    packed_corrected=_pack(src,layout)
    packed,invalid_blocks=_undo_block_sum_correction(packed_corrected,correction)
    groups_by_channel=[common._group_order(key,c,nblocks) for c in range(3)]
    failed=[]
    if invalid_blocks:
        for c,bid in invalid_blocks:
            ids=next(group for group in groups_by_channel[c] if bid in group)
            failed.append((c,int(ids[0])))
    restored=packed.copy(); received_groups=[]
    for c,groups in enumerate(groups_by_channel):
        for ids in groups:
            candidate=restored.copy()
            received=common._extract(candidate,common._slots(c,ids))
            if received is None:
                failed.append((c,int(ids[0])))
                continue
            restored=candidate
            received_groups.append((c,ids,received))

    for c,ids,received in received_groups:
        expected=_tag(key,iid,c,ids,restored,layout)
        if not hmac.compare_digest(received,expected):
            failed.append((c,int(ids[0])))
    if failed:
        reason=("invalid reversible block-sum correction and/or four-block HMAC tag; "
                "affected group(s) localized; plaintext withheld")
        return ExactVerification(False,reason,None,tuple(sorted(set(failed))),layout,payload_bits,tpe_identifier,iid)

    # Only after all group tags pass do we reverse Step-2 and Step-1, then the
    # logical pairing layout, returning the exact legacy TPE ciphertext.
    step1=common._auth_step2(restored,key,inverse=True)
    packed_tpe=common._auth_step1(step1,key,iid,inverse=True)
    tpe_cipher=_scatter(packed_tpe,layout)
    return ExactVerification(True,"all four-block HMAC tags accepted",tpe_cipher,(),layout,payload_bits,tpe_identifier,iid)


def decrypt_authenticated_tpe(marked_image: np.ndarray, layout_sidecar: bytes,
                              tpe_params: common.legacy.DemoPipelineParameters,
                              auth_key: bytes, auth_image_id: bytes | None = None,
                              tpe_image_identifier=None, expected_payload: Sequence[int] | None = None,
                              tpe_module=None) -> ExactDecryption:
    tpe_module=common.legacy if tpe_module is None else tpe_module
    verification=verify_tpe_ciphertext(marked_image,layout_sidecar,auth_key,auth_image_id)
    if not verification.accepted or verification.restored_tpe_ciphertext is None:
        return ExactDecryption(False,verification.reason,None,None,verification.failed_groups)
    auth_image_id=verification.auth_image_id
    stored_identifier=verification.tpe_image_identifier
    if tpe_image_identifier is not None and tpe_image_identifier != stored_identifier:
        return ExactDecryption(False,"TPE image identifier does not match authenticated sidecar metadata",None,None,())
    params=tpe_module.DemoPipelineParameters(
        block_size=tpe_params.block_size,key=tpe_params.key,
        image_identifier=stored_identifier,vartheta=tpe_params.vartheta)
    try:
        if getattr(tpe_module,"SIDECAR_PAYLOAD",False):
            decoded=tpe_module.decrypt_rgb_image(
                verification.restored_tpe_ciphertext,params,
                payload_bits=verification.recovered_payload_bits or [])
        else:
            decoded=tpe_module.decrypt_rgb_image(verification.restored_tpe_ciphertext,params)
    except Exception as exc:
        return ExactDecryption(False,f"authenticated TPE recovery failed: {type(exc).__name__}",None,None,())
    if expected_payload is not None and decoded.payload_bits!=list(expected_payload):
        return ExactDecryption(False,"authenticated image recovered but payload mismatch",decoded.recovered_image,decoded.payload_bits,())
    return ExactDecryption(True,"authenticated and exactly recovered",decoded.recovered_image,decoded.payload_bits,())


def decrypt_authenticated_tpe_bundle(marked_image: np.ndarray, layout_sidecar: bytes,
                                     tpe_key: bytes, auth_key: bytes,
                                     tpe_module=None) -> ExactDecryption:
    """Verify and recover a serialized PNG/sidecar bundle using only its keys.

    The public ImageID and dimensions are read from the authenticated sidecar
    header. The TPE schedule identifier and reversible metadata are opened
    from the AEAD-protected body. No EncryptionResult or plaintext is needed.
    """
    tpe_module=common.legacy if tpe_module is None else tpe_module
    params=tpe_module.DemoPipelineParameters(block_size=BLOCK,key=bytes(tpe_key))
    return decrypt_authenticated_tpe(marked_image,layout_sidecar,params,auth_key,
                                     None,None,None,tpe_module=tpe_module)

"""Research prototype combining legacy block-preserving TPE with RCM group authentication.

Pipeline follows the professor's flowchart at the component boundary:
  original -> existing blockwise TPE/RDH (block permutation + reversible
  substitution) -> HMAC-SHA256 per DRBG-selected group -> RCM reversible tag
  embedding -> authenticated TPE image.

Verification first extracts/restores each RCM mark and checks its tag. The
existing TPE decryption is called only after every group authenticates. Existing
cipher modules are not modified. This prototype supports image dimensions that
are multiples of 32 and whose block count is divisible by 4.
"""
from __future__ import annotations
from dataclasses import dataclass, replace
import hashlib, hmac, secrets
from pathlib import Path
import sys
from typing import Sequence
import numpy as np

_HERE=Path(__file__).resolve()
_AUTH_ROOT=_HERE.parents[1]
_REPO=_AUTH_ROOT.parent
sys.path.insert(0,str(_REPO/"tpe_rdh_reproduction"/"src"))
sys.path.insert(0,str(_AUTH_ROOT/"src"))
import pipeline as legacy
import atpe_v2 as auth_primitives
from permutation import permute_image_blocks, inverse_permute_image_blocks
from substitution import substitute_channel_blocks, inverse_substitute_channel_blocks
from rdh import embed_bits, extract_bits_and_recover

BLOCK=32
GROUP=4
TAG_BYTES=32
TAG_BITS=256
_DOMAIN=b"authenticated-tpe:block-group:v1\x00"

@dataclass(frozen=True)
class AuthenticatedCiphertext:
    marked_image: np.ndarray
    image_id: bytes
    mode: str
    groups: int

@dataclass(frozen=True)
class AuthVerification:
    accepted: bool
    reason: str
    restored_tpe_ciphertext: np.ndarray | None
    failed_groups: tuple[tuple[int,int], ...]
    mode: str | None = None

@dataclass(frozen=True)
class HybridEncryption:
    marked_image: np.ndarray
    image_id: bytes
    tpe_image_identifier: object
    auth_mode: str
    groups: int

@dataclass(frozen=True)
class HybridDecryption:
    accepted: bool
    reason: str
    recovered_image: np.ndarray | None
    recovered_payload_bits: list[int] | None
    failed_groups: tuple[tuple[int,int], ...]


def _dimensions(a: np.ndarray) -> tuple[int,int,int]:
    a=np.asarray(a)
    if a.ndim!=3 or a.dtype!=np.uint8 or a.shape[2]!=3:
        raise ValueError("image must be channel-last uint8 RGB")
    h,w,_=a.shape
    if h%BLOCK or w%BLOCK: raise ValueError("image dimensions must be multiples of 32")
    n=(h//BLOCK)*(w//BLOCK)
    if n<GROUP or n%GROUP: raise ValueError("each channel must contain a multiple of four 32x32 blocks")
    return h,w,n


def _block(a: np.ndarray,c:int,bid:int):
    blocks_x=a.shape[1]//BLOCK
    by,bx=divmod(bid,blocks_x)
    return a[by*BLOCK:(by+1)*BLOCK,bx*BLOCK:(bx+1)*BLOCK,c]


def _block_bytes(a:np.ndarray,c:int,bid:int)->bytes:
    return _block(a,c,bid).tobytes(order="C")


def _group_order(user_key:bytes,c:int,nblocks:int)->tuple[tuple[int,...],...]:
    """HMAC_DRBG Fisher-Yates grouping; unbiased 32-bit rejection sampling."""
    ks=auth_primitives.derive_keys(user_key,c)["Kstruct"]
    rng=auth_primitives.HMACDRBG(ks,b"",b"group-perm")
    perm=list(range(nblocks))
    for i in range(nblocks-1,0,-1):
        limit=((1<<32)//(i+1))*(i+1)
        x=rng.generate4()
        while x>=limit: x=rng.generate4()
        j=x%(i+1);perm[i],perm[j]=perm[j],perm[i]
    return tuple(tuple(perm[i:i+GROUP]) for i in range(0,nblocks,GROUP))


def _tag(user_key:bytes,image_id:bytes,c:int,ids:Sequence[int],a:np.ndarray)->bytes:
    kauth=auth_primitives.derive_keys(user_key)["Kauth"]
    gkey=auth_primitives.derive_group_key(kauth,image_id,c,ids)
    msg=bytearray(_DOMAIN+image_id+bytes([c]))
    for bid in ids: msg+=bid.to_bytes(2,"big")
    for bid in ids: msg+=_block_bytes(a,c,bid)
    return hmac.new(gkey,bytes(msg),hashlib.sha256).digest()


def _slots(c:int,ids:Sequence[int]):
    return [(c,bid,k) for k in range(BLOCK*BLOCK//2-1,-1,-1) for bid in ids]


def _whole_slots(nblocks:int):
    return [(c,bid,k) for k in range(BLOCK*BLOCK//2-1,-1,-1)
            for c in range(3) for bid in range(nblocks)]


def _whole_tag(user_key:bytes,image_id:bytes,a:np.ndarray)->bytes:
    kauth=auth_primitives.derive_keys(user_key)["Kauth"]
    kimage=auth_primitives.derive_image_key(kauth,image_id)
    msg=_DOMAIN+b"whole-image"+image_id+np.ascontiguousarray(a).tobytes(order="C")
    return hmac.new(kimage,msg,hashlib.sha256).digest()


def _auth_step1(a:np.ndarray,key:bytes,iid:bytes,inverse:bool=False)->np.ndarray:
    out=np.empty_like(a)
    for c in range(3):
        ktpe=auth_primitives.derive_keys(key,c)["Ktpe"]
        for bid in range((a.shape[0]//BLOCK)*(a.shape[1]//BLOCK)):
            for k in range(BLOCK*BLOCK//2):
                x,y=_get_pair(a,c,bid,k)
                q=(auth_primitives.inverse_step1_pair(x,y,ktpe,iid,bid,k)
                   if inverse else auth_primitives.step1_pair(x,y,ktpe,iid,bid,k))
                _put_pair(out,c,bid,k,*q)
    return out


def _auth_step2(a:np.ndarray,key:bytes,inverse:bool=False)->np.ndarray:
    out=np.empty_like(a)
    for c in range(3):
        kr1=auth_primitives.derive_keys(key,c)["Kr1"]
        for bid in range((a.shape[0]//BLOCK)*(a.shape[1]//BLOCK)):
            r1=auth_primitives.block_r1(kr1,bid)
            for k in range(BLOCK*BLOCK//2):
                x,y=_get_pair(a,c,bid,k)
                q=(auth_primitives.inverse_step2_pair(x,y,r1)
                   if inverse else auth_primitives.step2_pair(x,y,r1))
                _put_pair(out,c,bid,k,*q)
    return out


def _get_pair(a:np.ndarray,c:int,bid:int,k:int):
    blocks_x=a.shape[1]//BLOCK
    by,bx=divmod(bid,blocks_x)
    p0=2*k;p1=p0+1
    y0,x0=divmod(p0,BLOCK);y1,x1=divmod(p1,BLOCK)
    return (int(a[by*BLOCK+y0,bx*BLOCK+x0,c]),
            int(a[by*BLOCK+y1,bx*BLOCK+x1,c]))


def _put_pair(a:np.ndarray,c:int,bid:int,k:int,x:int,y:int):
    blocks_x=a.shape[1]//BLOCK
    by,bx=divmod(bid,blocks_x)
    p0=2*k;p1=p0+1
    y0,x0=divmod(p0,BLOCK);y1,x1=divmod(p1,BLOCK)
    a[by*BLOCK+y0,bx*BLOCK+x0,c]=x
    a[by*BLOCK+y1,bx*BLOCK+x1,c]=y


def _tag_bits(tag:bytes)->list[int]:
    return [(b>>i)&1 for b in tag for i in range(7,-1,-1)]


def _pack_tag(bits:Sequence[int])->bytes:
    if len(bits)!=TAG_BITS: raise ValueError("incorrect extracted tag length")
    return bytes(sum(int(bits[j+k])<<(7-k) for k in range(8)) for j in range(0,TAG_BITS,8))


def _embed(a:np.ndarray,slots:Sequence[tuple[int,int,int]],tag:bytes)->bool:
    plan=[];net=0;n_count=0
    for c,bid,k in slots:
        x,y=_get_pair(a,c,bid,k);kind=auth_primitives.classify_pair(x,y)
        saved=(x&1) if kind=="N" else 0
        plan.append((c,bid,k,kind,saved));net += -1 if kind=="N" else 1
        if kind=="N": n_count+=1
        if net>=TAG_BITS: break
    if net<TAG_BITS:return False
    stream=_tag_bits(tag)+[r[4] for r in plan if r[3]=="N"]
    cursor=0
    for c,bid,k,kind,_ in plan:
        x,y=_get_pair(a,c,bid,k)
        if kind=="T":
            xp,yp=auth_primitives.rcm_forward(x,y)
            _put_pair(a,c,bid,k,(xp&~1)|1,(yp&~1)|stream[cursor]);cursor+=1
        elif kind=="O":
            _put_pair(a,c,bid,k,x&~1,(y&~1)|stream[cursor]);cursor+=1
        else: _put_pair(a,c,bid,k,x&~1,y)
    if cursor!=TAG_BITS+n_count: raise AssertionError("tag/auxiliary bit accounting mismatch")
    return True


def _extract(a:np.ndarray,slots:Sequence[tuple[int,int,int]]):
    bits=[];nslots=[]
    for c,bid,k in slots:
        xp,yp=_get_pair(a,c,bid,k)
        if xp&1:
            bits.append(yp&1);x,y=auth_primitives.rcm_inverse(xp&~1,yp&~1)
            if not (0<=x<=255 and 0<=y<=255):return None
            _put_pair(a,c,bid,k,x,y)
        elif auth_primitives.base._in_dc(xp|1,yp|1):
            bits.append(yp&1);_put_pair(a,c,bid,k,xp|1,yp|1)
        else:
            nslots.append((c,bid,k))
        if len(bits)==TAG_BITS+len(nslots):
            saved=bits[TAG_BITS:]
            if len(saved)!=len(nslots):return None
            for (nc,nb,nk),lsb in zip(nslots,saved):
                x,y=_get_pair(a,nc,nb,nk);_put_pair(a,nc,nb,nk,(x&~1)|lsb,y)
            return _pack_tag(bits[:TAG_BITS])
    return None


def authenticate_tpe_ciphertext(tpe_ciphertext:np.ndarray,user_key:bytes,image_id:bytes|None=None)->AuthenticatedCiphertext:
    src=np.ascontiguousarray(tpe_ciphertext)
    _,_,nblocks=_dimensions(src)
    key=bytes(user_key)
    if len(key)<16:raise ValueError("authentication key must be at least 128 bits")
    iid=secrets.token_bytes(16) if image_id is None else bytes(image_id)
    if len(iid)!=16:raise ValueError("ImageID must be exactly 16 bytes")
    # Apply the flowchart's reversible pair transforms before computing tags.
    # Step 1 remains block-sum preserving; Step 2 and RCM marks are reversible.
    step1=_auth_step1(src,key,iid)
    step2=_auth_step2(step1,key)
    out=step2.copy();count=0;group_mode=True
    for c in range(3):
        for ids in _group_order(key,c,nblocks):
            tag=_tag(key,iid,c,ids,step1)
            if not _embed(out,_slots(c,ids),tag):
                group_mode=False
                break
            count+=1
        if not group_mode:break
    if group_mode:return AuthenticatedCiphertext(out,iid,"group",count)
    # As in the source authentication prototype, fall back atomically: discard
    # provisional group marks and authenticate the entire TPE ciphertext once.
    whole=step2.copy()
    if not _embed(whole,_whole_slots(nblocks),_whole_tag(key,iid,step1)):
        raise RuntimeError("insufficient RCM capacity in both group and whole-image modes")
    return AuthenticatedCiphertext(whole,iid,"whole-image",1)


def verify_tpe_ciphertext(marked:np.ndarray,user_key:bytes,image_id:bytes)->AuthVerification:
    src=np.ascontiguousarray(marked);_,_,nblocks=_dimensions(src)
    key=bytes(user_key);iid=bytes(image_id)
    if len(key)<16:raise ValueError("authentication key must be at least 128 bits")
    if len(iid)!=16:raise ValueError("ImageID must be exactly 16 bytes")
    restored=src.copy();failed=[];received_groups=[]
    for c in range(3):
        for ids in _group_order(key,c,nblocks):
            candidate=restored.copy()
            received=_extract(candidate,_slots(c,ids))
            if received is None:
                failed.append((c,ids[0]))
                break
            else:
                restored=candidate
                received_groups.append((c,ids,received))
        if failed:break
    if not failed:
        step1=_auth_step2(restored,key,inverse=True)
        if all(hmac.compare_digest(tag,_tag(key,iid,c,ids,step1)) for c,ids,tag in received_groups):
            base_cipher=_auth_step1(step1,key,iid,inverse=True)
            return AuthVerification(True,"all group HMACs accepted",base_cipher,(),"group")
        failed=[(c,ids[0]) for c,ids,tag in received_groups
                if not hmac.compare_digest(tag,_tag(key,iid,c,ids,step1))]
    # A whole-image mark is the declared capacity fallback. Never expose the
    # partially tested group candidate; retry extraction from the untouched input.
    whole=src.copy()
    received=_extract(whole,_whole_slots(nblocks))
    if received is not None:
        step1=_auth_step2(whole,key,inverse=True)
        if hmac.compare_digest(received,_whole_tag(key,iid,step1)):
            base_cipher=_auth_step1(step1,key,iid,inverse=True)
            return AuthVerification(True,"whole-image HMAC accepted (capacity fallback)",base_cipher,(),"whole-image")
    return AuthVerification(False,"group and whole-image HMAC verification failed; plaintext withheld",None,tuple(failed))


def encrypt_authenticated_tpe(image:np.ndarray,payload_bits:Sequence[int],tpe_params:legacy.DemoPipelineParameters,auth_key:bytes,auth_image_id:bytes|None=None)->HybridEncryption:
    """Authenticate the sum-preserving image, then apply reversible Step 2.

    The source chaotic substitution is an exact pair-sum-preserving bijection,
    but its output histogram does not provide enough RCM T/O/N capacity for
    these 256-bit group tags. Therefore we apply RCM to the preceding
    thumbnail-preserving carrier, then wrap it in the source Step-2 transform.
    Decryption first inverts Step 2 and only then verifies/extracts RCM. This
    changes the ordering at a reversible boundary; it does not alter the source
    transform or authentication primitive and keeps block sums/block effect.
    """
    source=np.ascontiguousarray(image);h,w,_=_dimensions(source)
    if tpe_params.block_size!=BLOCK:
        raise ValueError("hybrid authentication prototype requires 32x32 TPE blocks")
    payload=legacy._validate_bits(payload_bits)
    tpe_id=legacy._resolve_encryption_identifier(source,tpe_params.image_identifier)
    upsilon_p,upsilon_s=legacy.generate_upsilon_matrices(h,w,tpe_params.key,tpe_id)
    permuted=permute_image_blocks(source,upsilon_p,BLOCK)
    channel_payloads=legacy._split_payload_across_channels(payload,3)
    rdh_channels=[]
    for c,part in enumerate(channel_payloads):
        marked,_info=embed_bits(permuted[:,:,c],part)
        rdh_channels.append(marked)
    carrier=np.stack(rdh_channels,axis=2)
    auth=authenticate_tpe_ciphertext(carrier,auth_key,auth_image_id)
    encrypted=np.stack([
        substitute_channel_blocks(auth.marked_image[:,:,c],upsilon_s,BLOCK,tpe_params.vartheta)
        for c in range(3)
    ],axis=2)
    return HybridEncryption(encrypted,auth.image_id,tpe_id,auth.mode,auth.groups)


def decrypt_authenticated_tpe(marked:np.ndarray,payload_bits:Sequence[int],tpe_params:legacy.DemoPipelineParameters,auth_key:bytes,auth_image_id:bytes,tpe_image_identifier)->HybridDecryption:
    """Invert source Step 2, verify HMAC/RCM, then reverse RDH and TPE."""
    src=np.ascontiguousarray(marked);h,w,_=_dimensions(src)
    if tpe_params.block_size!=BLOCK:
        raise ValueError("hybrid authentication prototype requires 32x32 TPE blocks")
    upsilon_p,upsilon_s=legacy.generate_upsilon_matrices(h,w,tpe_params.key,tpe_image_identifier)
    carrier=np.stack([
        inverse_substitute_channel_blocks(src[:,:,c],upsilon_s,BLOCK,tpe_params.vartheta)
        for c in range(3)
    ],axis=2)
    v=verify_tpe_ciphertext(carrier,auth_key,auth_image_id)
    if not v.accepted:return HybridDecryption(False,v.reason,None,None,v.failed_groups)
    recovered_channels=[];extracted=[]
    for c in range(3):
        bits,channel=extract_bits_and_recover(v.restored_tpe_ciphertext[:,:,c])
        extracted.append(bits);recovered_channels.append(channel)
    recovered_permuted=np.stack(recovered_channels,axis=2)
    recovered=inverse_permute_image_blocks(recovered_permuted,upsilon_p,BLOCK)
    recovered_payload=[bit for part in extracted for bit in part]
    payload_ok=recovered_payload==list(payload_bits)
    return HybridDecryption(payload_ok,"authenticated and exactly recovered" if payload_ok else "authenticated but payload mismatch",recovered,recovered_payload,())


def block_thumbnail(a:np.ndarray,block_size:int=32)->np.ndarray:
    """Rounded block-average RGB thumbnail, for explicit fidelity reporting."""
    x=np.asarray(a)
    h,w,_=_dimensions(x)
    view=x.reshape(h//block_size,block_size,w//block_size,block_size,3).astype(np.float64)
    return np.rint(view.mean(axis=(1,3))).clip(0,255).astype(np.uint8)

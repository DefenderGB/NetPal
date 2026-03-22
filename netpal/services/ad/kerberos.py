"""Pure-Python Kerberos AS-REQ client for TGT acquisition.

Implements Kerberos pre-authentication and TGT retrieval using AES keys
or NTLM hashes, without requiring impacket. Uses pyasn1 for ASN.1
encoding/decoding and pycryptodome for AES-CTS-HMAC-SHA1 encryption.

Supports:
- AES256-CTS-HMAC-SHA1-96 (etype 18) pre-auth + TGT
- AES128-CTS-HMAC-SHA1-96 (etype 17) pre-auth + TGT
- RC4-HMAC (etype 23) pre-auth + TGT (pass-the-hash with NT hash)
- Writes standard MIT ccache files for use with GSSAPI/ldap3

References:
- RFC 4120: The Kerberos Network Authentication Service (V5)
- RFC 3962: AES Encryption for Kerberos 5
- RFC 4757: RC4-HMAC Kerberos Encryption Type
- MS-KILE: Microsoft Kerberos Protocol Extensions
"""
import hashlib
import hmac
import logging
import os
import secrets
import socket
import struct
import tempfile
import time
from datetime import datetime, timezone

log = logging.getLogger(__name__)

# ── Kerberos constants ────────────────────────────────────────────────
KRB5_PVNO = 5
KRB_AS_REQ = 10
KRB_AS_REP = 11
KRB_ERROR = 30

ETYPE_AES256 = 18
ETYPE_AES128 = 17
ETYPE_RC4_HMAC = 23

PA_ENC_TIMESTAMP = 2
PA_PAC_REQUEST = 128

KDC_OPT_FORWARDABLE = 0x40000000
KDC_OPT_RENEWABLE = 0x00800000
KDC_OPT_CANONICALIZE = 0x00010000

NT_PRINCIPAL = 1
NT_SRV_INST = 2

KEY_USAGE_PA_ENC_TIMESTAMP = 1
KEY_USAGE_AS_REP_ENCPART = 3

AES_BLOCK = 16


# ── Exceptions ────────────────────────────────────────────────────────

class KerberosError(Exception):
    """Raised when a Kerberos operation fails."""

    def __init__(self, message: str, error_code: int = 0):
        self.error_code = error_code
        super().__init__(message)


# ── ASN.1 DER helpers (minimal, no pyasn1 dependency for building) ───
# We hand-craft DER encoding for AS-REQ to avoid heavy pyasn1 usage
# on the encode side, and use pyasn1 only for decoding AS-REP.

def _der_len(length: int) -> bytes:
    """Encode a DER length field."""
    if length < 0x80:
        return bytes([length])
    elif length < 0x100:
        return bytes([0x81, length])
    elif length < 0x10000:
        return bytes([0x82, (length >> 8) & 0xFF, length & 0xFF])
    else:
        return bytes([0x83, (length >> 16) & 0xFF,
                      (length >> 8) & 0xFF, length & 0xFF])


def _der_tag(tag_class: int, constructed: bool, tag_num: int,
             value: bytes) -> bytes:
    """Build a DER TLV (tag-length-value)."""
    if tag_num < 31:
        tag_byte = (tag_class << 6) | (0x20 if constructed else 0) | tag_num
        return bytes([tag_byte]) + _der_len(len(value)) + value
    # High-tag-number form (not needed for Kerberos)
    raise ValueError(f"Tag number {tag_num} >= 31 not supported")


def _der_seq(items: list[bytes]) -> bytes:
    """Build a DER SEQUENCE."""
    body = b"".join(items)
    return b"\x30" + _der_len(len(body)) + body


def _der_int(val: int) -> bytes:
    """Encode a DER INTEGER."""
    if val == 0:
        return b"\x02\x01\x00"
    neg = val < 0
    if neg:
        val = -val - 1
    # Determine byte length
    byte_len = (val.bit_length() + 8) // 8
    raw = val.to_bytes(byte_len, "big")
    if neg:
        raw = bytes(b ^ 0xFF for b in raw)
    # Ensure proper sign bit
    if not neg and raw[0] & 0x80:
        raw = b"\x00" + raw
    return b"\x02" + _der_len(len(raw)) + raw


def _der_octet(data: bytes) -> bytes:
    """Encode a DER OCTET STRING."""
    return b"\x04" + _der_len(len(data)) + data


def _der_general_string(s: str) -> bytes:
    """Encode a DER GeneralString."""
    raw = s.encode("ascii")
    return b"\x1b" + _der_len(len(raw)) + raw


def _der_generalized_time(dt: datetime) -> bytes:
    """Encode a DER GeneralizedTime."""
    s = dt.strftime("%Y%m%d%H%M%SZ").encode("ascii")
    return b"\x18" + _der_len(len(s)) + s


def _der_bitstring(data: bytes) -> bytes:
    """Encode a DER BIT STRING (no unused bits)."""
    body = b"\x00" + data  # 0 unused bits
    return b"\x03" + _der_len(len(body)) + body


def _ctx(tag_num: int, value: bytes, constructed: bool = True) -> bytes:
    """Context-specific tagged value [N]."""
    return _der_tag(2, constructed, tag_num, value)



# ── Crypto: AES-CTS-HMAC-SHA1 (RFC 3962) ─────────────────────────────

def _aes_encrypt_cbc(key: bytes, iv: bytes, data: bytes) -> bytes:
    """Raw AES-CBC encrypt (no padding)."""
    from Crypto.Cipher import AES
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(data)


def _aes_decrypt_cbc(key: bytes, iv: bytes, data: bytes) -> bytes:
    """Raw AES-CBC decrypt (no padding)."""
    from Crypto.Cipher import AES
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.decrypt(data)


def _aes_cts_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """AES-CTS (ciphertext stealing) encrypt per RFC 3962.

    Input must be >= 16 bytes (one AES block). Uses confounder (random
    block) prepended by caller. Output is same length as input.
    """
    if len(plaintext) < AES_BLOCK:
        raise ValueError("AES-CTS plaintext must be >= 16 bytes")

    nblocks = (len(plaintext) + AES_BLOCK - 1) // AES_BLOCK
    iv = b"\x00" * AES_BLOCK

    if nblocks == 1:
        return _aes_encrypt_cbc(key, iv, plaintext)

    # Pad to full block boundary for CBC
    last_block_len = len(plaintext) % AES_BLOCK
    if last_block_len == 0:
        last_block_len = AES_BLOCK

    # Encrypt all but last partial block with CBC
    full_len = (nblocks - 1) * AES_BLOCK
    cbc_input = plaintext[:full_len]
    cbc_out = _aes_encrypt_cbc(key, iv, cbc_input)

    # Last full ciphertext block becomes the new IV
    prev_ct = cbc_out[-AES_BLOCK:]

    # Pad the last partial block with zeros, encrypt
    last_plain = plaintext[full_len:]
    padded = last_plain + b"\x00" * (AES_BLOCK - len(last_plain))
    last_ct = _aes_encrypt_cbc(key, prev_ct, padded)

    # CTS swap: output is [CBC blocks except last] + [last_ct] + [truncated prev_ct]
    # Actually for Kerberos CTS: swap last two ciphertext blocks
    return cbc_out[:-AES_BLOCK] + last_ct + prev_ct[:last_block_len]


def _aes_cts_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    """AES-CTS (ciphertext stealing) decrypt per RFC 3962."""
    if len(ciphertext) < AES_BLOCK:
        raise ValueError("AES-CTS ciphertext must be >= 16 bytes")

    nblocks = (len(ciphertext) + AES_BLOCK - 1) // AES_BLOCK
    iv = b"\x00" * AES_BLOCK

    if nblocks == 1:
        return _aes_decrypt_cbc(key, iv, ciphertext)

    last_block_len = len(ciphertext) % AES_BLOCK
    if last_block_len == 0:
        last_block_len = AES_BLOCK

    # Split: all-but-last-two | second-to-last (full) | last (partial)
    if nblocks == 2:
        prefix = b""
    else:
        prefix_len = (nblocks - 2) * AES_BLOCK
        prefix = ciphertext[:prefix_len]

    second_last = ciphertext[len(prefix):len(prefix) + AES_BLOCK]
    last = ciphertext[len(prefix) + AES_BLOCK:]

    # Decrypt second-to-last block to get padded plaintext of last block
    if prefix:
        # IV for second-to-last is the last block of prefix CBC
        prev_iv = _aes_encrypt_cbc(key, iv, prefix)[-AES_BLOCK:]
        # Actually we need to decrypt, so we need the ciphertext block before
        prev_iv = prefix[-AES_BLOCK:]
    else:
        prev_iv = iv

    # Decrypt second_last to get intermediate
    intermediate = _aes_decrypt_cbc(key, b"\x00" * AES_BLOCK, second_last)

    # Recover last plaintext: XOR intermediate with padded last ciphertext
    padded_last = last + intermediate[last_block_len:]
    last_plain = bytes(a ^ b for a, b in zip(intermediate, padded_last))
    last_plain = last_plain[:last_block_len]

    # Now decrypt the rest with CBC, using padded_last as the second-to-last ciphertext
    if prefix:
        cbc_ct = prefix + padded_last
    else:
        cbc_ct = padded_last

    cbc_plain = _aes_decrypt_cbc(key, iv, cbc_ct)

    return cbc_plain + last_plain


def _dk(key: bytes, usage: bytes, key_len: int) -> bytes:
    """Derive key using DK(Key, Constant) per RFC 3961 simplified profile.

    DK(Key, Constant) = random-to-key(DR(Key, Constant))
    DR uses n-fold and CBC encryption to derive key material.
    """
    # n-fold the constant to the cipher block size
    folded = _nfold(usage, AES_BLOCK * 8)

    # Generate enough key material
    result = b""
    ki = folded
    while len(result) < key_len:
        ki = _aes_encrypt_cbc(key, b"\x00" * AES_BLOCK, ki)
        result += ki

    return result[:key_len]


def _nfold(data: bytes, nbits: int) -> bytes:
    """N-fold operation per RFC 3961 §5.1.

    Replicate input to LCM(input_len, output_len) bits, rotating right
    by 13 bits each repetition, then split into output-sized chunks and
    sum them using 1's-complement (end-around carry) addition.

    Reference: RFC 3961 section 5.1, Blumenthal96.
    """
    inbytes = len(data)
    inbits = inbytes * 8
    outbytes = nbits // 8

    from math import gcd
    lcm_val = (inbits * nbits) // gcd(inbits, nbits)

    # Number of copies of the input needed to fill LCM bits
    num_copies = lcm_val // inbits

    # Build the LCM-length bit string by concatenating rotated copies.
    # Work as a big integer in bit space.
    # "rotate right by 13" on the input bit string.
    def rotate_right_bits(val: int, rot: int, width: int) -> int:
        rot = rot % width
        if rot == 0:
            return val
        return ((val >> rot) | (val << (width - rot))) & ((1 << width) - 1)

    # Convert input to integer (big-endian, MSB first)
    in_val = int.from_bytes(data, "big")

    # Build the full LCM-length string as a big integer
    # Each copy is rotated right by 13*i bits from the original
    full_val = 0
    for i in range(num_copies):
        rotated = rotate_right_bits(in_val, 13 * i, inbits)
        # Shift left to make room and OR in
        full_val = (full_val << inbits) | rotated

    # Now split into outbytes-sized chunks and add with 1's-complement
    num_chunks = lcm_val // nbits
    mask = (1 << nbits) - 1

    result = 0
    for i in range(num_chunks):
        # Extract chunk from the right (last chunk first)
        shift = i * nbits
        chunk = (full_val >> shift) & mask
        # 1's-complement addition
        result = _ones_complement_add(result, chunk, nbits)

    return result.to_bytes(outbytes, "big")


def _ones_complement_add(a: int, b: int, width: int) -> int:
    """Add two integers using 1's-complement arithmetic (end-around carry)."""
    mask = (1 << width) - 1
    s = a + b
    while s > mask:
        # End-around carry: add the overflow bits back
        s = (s & mask) + (s >> width)
    return s


def _derive_key(base_key: bytes, key_usage: int, key_type: str) -> bytes:
    """Derive Ke (encryption) or Ki (integrity) key for a given usage.

    Per RFC 3962: Ke = DK(base, usage || 0xAA), Ki = DK(base, usage || 0x55)
    """
    usage_bytes = struct.pack(">I", key_usage)
    if key_type == "enc":
        constant = usage_bytes + b"\xaa"
    elif key_type == "int":
        constant = usage_bytes + b"\x55"
    else:
        raise ValueError(f"Unknown key_type: {key_type}")
    return _dk(base_key, constant, len(base_key))


def _hmac_sha1(key: bytes, data: bytes) -> bytes:
    """HMAC-SHA1."""
    return hmac.new(key, data, hashlib.sha1).digest()


def aes_encrypt(key: bytes, key_usage: int, plaintext: bytes) -> bytes:
    """Encrypt using AES-CTS-HMAC-SHA1-96 (RFC 3962).

    Returns: confounder + AES-CTS(confounder + plaintext) + HMAC-SHA1-96
    The output format is: EncryptedData value (cipher field).
    """
    ke = _derive_key(key, key_usage, "enc")
    ki = _derive_key(key, key_usage, "int")

    confounder = secrets.token_bytes(AES_BLOCK)
    to_encrypt = confounder + plaintext

    # Pad to at least one block
    if len(to_encrypt) < AES_BLOCK:
        to_encrypt += b"\x00" * (AES_BLOCK - len(to_encrypt))

    encrypted = _aes_cts_encrypt(ke, to_encrypt)
    checksum = _hmac_sha1(ki, to_encrypt)[:12]  # Truncate to 96 bits

    return encrypted + checksum


def aes_decrypt(key: bytes, key_usage: int, ciphertext: bytes) -> bytes:
    """Decrypt using AES-CTS-HMAC-SHA1-96 (RFC 3962).

    Input format: AES-CTS ciphertext + 12-byte HMAC.
    Returns: plaintext (without confounder).
    """
    if len(ciphertext) < AES_BLOCK + 12:
        raise KerberosError("Ciphertext too short for AES-CTS-HMAC-SHA1")

    ke = _derive_key(key, key_usage, "enc")
    ki = _derive_key(key, key_usage, "int")

    ct_body = ciphertext[:-12]
    expected_hmac = ciphertext[-12:]

    decrypted = _aes_cts_decrypt(ke, ct_body)

    # Verify HMAC
    actual_hmac = _hmac_sha1(ki, decrypted)[:12]
    if not hmac.compare_digest(actual_hmac, expected_hmac):
        raise KerberosError("AES-CTS HMAC verification failed — wrong key?")

    # Strip confounder (first 16 bytes)
    return decrypted[AES_BLOCK:]



# ── Crypto: RC4-HMAC (RFC 4757) ──────────────────────────────────────

def rc4_encrypt(key: bytes, key_usage: int, plaintext: bytes) -> bytes:
    """Encrypt using RC4-HMAC (etype 23) per RFC 4757.

    key is the raw 16-byte NT hash.
    """
    from Crypto.Cipher import ARC4

    # K1 = HMAC-MD5(key, usage_le)
    k1 = hmac.new(key, struct.pack("<I", key_usage), hashlib.md5).digest()

    confounder = secrets.token_bytes(8)
    to_encrypt = confounder + plaintext

    # Checksum = HMAC-MD5(K1, plaintext_with_confounder)
    checksum = hmac.new(k1, to_encrypt, hashlib.md5).digest()

    # K3 = HMAC-MD5(K1, checksum)
    k3 = hmac.new(k1, checksum, hashlib.md5).digest()

    cipher = ARC4.new(k3)
    encrypted = cipher.encrypt(to_encrypt)

    return checksum + encrypted


def rc4_decrypt(key: bytes, key_usage: int, ciphertext: bytes) -> bytes:
    """Decrypt using RC4-HMAC (etype 23) per RFC 4757."""
    from Crypto.Cipher import ARC4

    if len(ciphertext) < 24:  # 16 checksum + 8 confounder minimum
        raise KerberosError("RC4-HMAC ciphertext too short")

    checksum = ciphertext[:16]
    encrypted = ciphertext[16:]

    k1 = hmac.new(key, struct.pack("<I", key_usage), hashlib.md5).digest()
    k3 = hmac.new(k1, checksum, hashlib.md5).digest()

    cipher = ARC4.new(k3)
    decrypted = cipher.decrypt(encrypted)

    # Verify checksum
    expected = hmac.new(k1, decrypted, hashlib.md5).digest()
    if not hmac.compare_digest(expected, checksum):
        raise KerberosError("RC4-HMAC checksum verification failed — wrong key?")

    # Strip 8-byte confounder
    return decrypted[8:]


# ── ASN.1 building: Kerberos AS-REQ ──────────────────────────────────

def _build_principal_name(name_type: int, components: list[str]) -> bytes:
    """Build a PrincipalName SEQUENCE."""
    name_strings = _der_seq([_der_general_string(c) for c in components])
    return _der_seq([
        _ctx(0, _der_int(name_type)),
        _ctx(1, name_strings),
    ])


def _build_pa_enc_timestamp(key: bytes, etype: int) -> bytes:
    """Build PA-ENC-TIMESTAMP pre-auth data.

    Encrypts current timestamp with the provided key.
    """
    now = datetime.now(timezone.utc)
    # PA-ENC-TS-ENC ::= SEQUENCE { patimestamp[0] KerberosTime, pausec[1] INTEGER }
    ts_enc = _der_seq([
        _ctx(0, _der_generalized_time(now)),
        _ctx(1, _der_int(now.microsecond)),
    ])

    if etype in (ETYPE_AES256, ETYPE_AES128):
        cipher = aes_encrypt(key, KEY_USAGE_PA_ENC_TIMESTAMP, ts_enc)
    elif etype == ETYPE_RC4_HMAC:
        cipher = rc4_encrypt(key, KEY_USAGE_PA_ENC_TIMESTAMP, ts_enc)
    else:
        raise KerberosError(f"Unsupported etype for pre-auth: {etype}")

    # EncryptedData ::= SEQUENCE { etype[0], kvno[1] OPTIONAL, cipher[2] }
    enc_data = _der_seq([
        _ctx(0, _der_int(etype)),
        _ctx(2, _der_octet(cipher)),
    ])

    return enc_data


def _build_pa_pac_request(include_pac: bool = True) -> bytes:
    """Build KERB-PA-PAC-REQUEST."""
    # KERB-PA-PAC-REQUEST ::= SEQUENCE { include-pac[0] BOOLEAN }
    bool_val = b"\x01\x01" + (b"\xff" if include_pac else b"\x00")
    return _der_seq([_ctx(0, bool_val)])


def _build_as_req(
    domain: str,
    username: str,
    key: bytes,
    etype: int,
    nonce: int | None = None,
) -> bytes:
    """Build a complete Kerberos AS-REQ message.

    Args:
        domain: Kerberos realm (e.g. 'CORP.LOCAL').
        username: Client principal name (e.g. 'admin').
        key: Encryption key (AES key bytes or 16-byte NT hash).
        etype: Encryption type (17, 18, or 23).
        nonce: Random nonce (auto-generated if None).

    Returns:
        DER-encoded AS-REQ bytes ready to send to KDC.
    """
    realm = domain.upper()
    if nonce is None:
        nonce = secrets.randbelow(2**31)

    # KDC options
    kdc_options = KDC_OPT_FORWARDABLE | KDC_OPT_RENEWABLE | KDC_OPT_CANONICALIZE
    kdc_opts_bytes = struct.pack(">I", kdc_options)

    # Client name
    cname = _build_principal_name(NT_PRINCIPAL, [username])

    # Server name (krbtgt/REALM)
    sname = _build_principal_name(NT_SRV_INST, ["krbtgt", realm])

    # Till time (far future)
    till = datetime(2037, 9, 13, 2, 48, 5, tzinfo=timezone.utc)

    # Etype list
    etype_seq = _der_seq([_der_int(etype)])

    # REQ-BODY
    req_body = _der_seq([
        _ctx(0, _der_bitstring(kdc_opts_bytes)),
        _ctx(1, cname),
        _ctx(2, _der_general_string(realm)),
        _ctx(3, sname),
        _ctx(5, _der_generalized_time(till)),
        _ctx(7, _der_int(nonce)),
        _ctx(8, etype_seq),
    ])

    # PA-DATA: encrypted timestamp
    pa_timestamp = _build_pa_enc_timestamp(key, etype)
    pa_ts_data = _der_seq([
        _ctx(1, _der_int(PA_ENC_TIMESTAMP)),
        _ctx(2, _der_octet(pa_timestamp)),
    ])

    # PA-DATA: PAC request
    pa_pac = _build_pa_pac_request(True)
    pa_pac_data = _der_seq([
        _ctx(1, _der_int(PA_PAC_REQUEST)),
        _ctx(2, _der_octet(pa_pac)),
    ])

    padata_seq = _der_seq([pa_ts_data, pa_pac_data])

    # KDC-REQ (AS-REQ) body
    kdc_req_body = _der_seq([
        _ctx(1, _der_int(KRB5_PVNO)),
        _ctx(2, _der_int(KRB_AS_REQ)),
        _ctx(3, padata_seq),
        _ctx(4, req_body),
    ])

    # Wrap in APPLICATION [10] (AS-REQ)
    as_req = _der_tag(1, True, 10, kdc_req_body)

    return as_req



# ── ASN.1 parsing: Kerberos AS-REP / KRB-ERROR ───────────────────────
# Minimal DER decoder — avoids full pyasn1 dependency for parsing.

def _der_decode_tlv(data: bytes, offset: int = 0) -> tuple:
    """Decode one DER TLV at offset. Returns (tag, constructed, value, next_offset)."""
    if offset >= len(data):
        raise KerberosError("DER decode: unexpected end of data")

    tag_byte = data[offset]
    tag_class = (tag_byte >> 6) & 0x03
    constructed = bool(tag_byte & 0x20)
    tag_num = tag_byte & 0x1F
    offset += 1

    if tag_num == 0x1F:
        # High tag number
        tag_num = 0
        while True:
            b = data[offset]
            offset += 1
            tag_num = (tag_num << 7) | (b & 0x7F)
            if not (b & 0x80):
                break

    # Length
    len_byte = data[offset]
    offset += 1
    if len_byte < 0x80:
        length = len_byte
    elif len_byte == 0x80:
        raise KerberosError("Indefinite length not supported")
    else:
        num_bytes = len_byte & 0x7F
        length = int.from_bytes(data[offset:offset + num_bytes], "big")
        offset += num_bytes

    value = data[offset:offset + length]
    return (tag_byte, tag_class, constructed, tag_num, value, offset + length)


def _der_decode_seq(data: bytes) -> list:
    """Decode a DER SEQUENCE into list of (tag_byte, value) tuples."""
    items = []
    offset = 0
    while offset < len(data):
        tag_byte, tag_class, constructed, tag_num, value, offset = \
            _der_decode_tlv(data, offset)
        items.append((tag_byte, tag_class, constructed, tag_num, value))
    return items


def _der_decode_int(data: bytes) -> int:
    """Decode a DER INTEGER value."""
    return int.from_bytes(data, "big", signed=True)


def _unwrap_ctx(data: bytes, expected_tag: int) -> bytes:
    """Unwrap a context-specific [N] tag, return inner value."""
    tag_byte, _, constructed, tag_num, value, _ = _der_decode_tlv(data)
    if tag_num != expected_tag:
        raise KerberosError(
            f"Expected context tag [{expected_tag}], got [{tag_num}]")
    return value


def _parse_as_rep(data: bytes) -> dict:
    """Parse a DER-encoded AS-REP into a dict.

    Returns dict with keys: pvno, msg_type, crealm, cname, ticket, enc_part.
    ticket and enc_part are raw bytes for further processing.
    """
    # Unwrap APPLICATION tag
    tag_byte, tag_class, constructed, tag_num, body, _ = _der_decode_tlv(data)

    if tag_num == 30:
        # KRB-ERROR
        return _parse_krb_error(body)

    if tag_num != 11:
        raise KerberosError(f"Expected AS-REP (tag 11), got tag {tag_num}")

    # Parse the SEQUENCE inside
    items = _der_decode_seq(body)
    result = {"msg_type": KRB_AS_REP}

    for tag_byte, tag_class, constructed, tag_num, value in items:
        if tag_class == 2:  # Context-specific
            if tag_num == 0:  # pvno
                inner = _der_decode_tlv(value)[4]
                result["pvno"] = _der_decode_int(inner)
            elif tag_num == 1:  # msg-type
                inner = _der_decode_tlv(value)[4]
                result["msg_type"] = _der_decode_int(inner)
            elif tag_num == 3:  # crealm
                result["crealm"] = value.decode("ascii", errors="replace")
            elif tag_num == 5:  # ticket (raw)
                result["ticket_raw"] = _der_tag(1, True, tag_num, value)
                # Re-encode the full ticket for ccache
                result["ticket_der"] = value
                # Parse to get the APPLICATION [1] wrapped ticket
                # The value here is the inner SEQUENCE of the Ticket
                # We need the full APPLICATION [1] CONSTRUCTED wrapper
            elif tag_num == 6:  # enc-part
                result["enc_part_raw"] = value

    # Parse enc-part to get etype and cipher
    if "enc_part_raw" in result:
        enc_items = _der_decode_seq(result["enc_part_raw"])
        for tag_byte, tag_class, constructed, tag_num, value in enc_items:
            if tag_class == 2:
                if tag_num == 0:  # etype
                    inner = _der_decode_tlv(value)[4]
                    result["enc_etype"] = _der_decode_int(inner)
                elif tag_num == 2:  # cipher
                    inner = _der_decode_tlv(value)[4]
                    result["enc_cipher"] = inner

    # Re-extract the raw ticket bytes (APPLICATION [1] wrapped)
    # We need to find it in the original body
    result["ticket_bytes"] = _extract_ticket_from_as_rep(data)

    return result


def _extract_ticket_from_as_rep(data: bytes) -> bytes:
    """Extract the raw Ticket (APPLICATION [1]) from AS-REP bytes.

    Scans the AS-REP for the context [5] tag containing the Ticket,
    and returns the inner APPLICATION [1] tagged Ticket.
    """
    # Unwrap APPLICATION [11]
    _, _, _, _, body, _ = _der_decode_tlv(data)
    # Scan SEQUENCE items
    offset = 0
    while offset < len(body):
        tag_byte, tag_class, constructed, tag_num, value, next_off = \
            _der_decode_tlv(body, offset)
        if tag_class == 2 and tag_num == 5:
            # This is [5] Ticket — value contains APPLICATION [1] Ticket
            return value
        offset = next_off
    raise KerberosError("Could not find Ticket in AS-REP")


def _parse_krb_error(body: bytes) -> dict:
    """Parse KRB-ERROR body."""
    items = _der_decode_seq(body)
    result = {"msg_type": KRB_ERROR}

    for tag_byte, tag_class, constructed, tag_num, value in items:
        if tag_class == 2:
            if tag_num == 4:  # stime
                result["stime"] = value.decode("ascii", errors="replace")
            elif tag_num == 6:  # error-code
                inner = _der_decode_tlv(value)[4]
                result["error_code"] = _der_decode_int(inner)
            elif tag_num == 8:  # crealm
                result["crealm"] = value.decode("ascii", errors="replace")
            elif tag_num == 11:  # e-text
                result["e_text"] = value.decode("ascii", errors="replace")

    return result


def _parse_enc_as_rep_part(data: bytes) -> dict:
    """Parse decrypted EncASRepPart / EncKDCRepPart.

    Returns dict with: key_type, key_value, nonce, authtime, endtime, etc.
    """
    # May be wrapped in APPLICATION [25] (EncASRepPart) or [26] (EncTGSRepPart)
    tag_byte, tag_class, constructed, tag_num, body, _ = _der_decode_tlv(data)

    if tag_class == 1:  # APPLICATION
        # Unwrap APPLICATION tag, body is the SEQUENCE
        pass
    else:
        # Might be a raw SEQUENCE
        body = data

    # If body starts with SEQUENCE tag, parse it
    if body[0] == 0x30:
        _, _, _, _, body, _ = _der_decode_tlv(body)

    items = _der_decode_seq(body)
    result = {}

    for tag_byte, tag_class, constructed, tag_num, value in items:
        if tag_class == 2:
            if tag_num == 0:  # key (EncryptionKey)
                key_items = _der_decode_seq(value)
                for kt, kc, _, kn, kv in key_items:
                    if kc == 2 and kn == 0:  # keytype
                        inner = _der_decode_tlv(kv)[4]
                        result["key_type"] = _der_decode_int(inner)
                    elif kc == 2 and kn == 1:  # keyvalue
                        inner = _der_decode_tlv(kv)[4]
                        result["key_value"] = inner
            elif tag_num == 2:  # nonce
                inner = _der_decode_tlv(value)[4]
                result["nonce"] = _der_decode_int(inner)
            elif tag_num == 5:  # authtime
                result["authtime"] = value.decode("ascii", errors="replace")
            elif tag_num == 6:  # starttime
                result["starttime"] = value.decode("ascii", errors="replace")
            elif tag_num == 7:  # endtime
                result["endtime"] = value.decode("ascii", errors="replace")
            elif tag_num == 8:  # renew-till
                result["renew_till"] = value.decode("ascii", errors="replace")
            elif tag_num == 9:  # srealm
                result["srealm"] = value.decode("ascii", errors="replace")

    return result



# ── Network: KDC communication ────────────────────────────────────────

def _send_kdc_request(kdc_host: str, data: bytes, timeout: int = 30) -> bytes:
    """Send a Kerberos request to KDC over TCP and return the response.

    Kerberos over TCP uses a 4-byte big-endian length prefix.
    """
    # TCP framing: 4-byte length prefix
    framed = struct.pack(">I", len(data)) + data

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((kdc_host, 88))
        sock.sendall(framed)

        # Read 4-byte length
        resp_len_raw = b""
        while len(resp_len_raw) < 4:
            chunk = sock.recv(4 - len(resp_len_raw))
            if not chunk:
                raise KerberosError("KDC closed connection before sending response length")
            resp_len_raw += chunk

        resp_len = struct.unpack(">I", resp_len_raw)[0]
        if resp_len > 10 * 1024 * 1024:  # 10MB sanity limit
            raise KerberosError(f"KDC response too large: {resp_len} bytes")

        # Read response body
        resp = b""
        while len(resp) < resp_len:
            chunk = sock.recv(min(resp_len - len(resp), 65536))
            if not chunk:
                raise KerberosError("KDC closed connection during response")
            resp += chunk

        return resp

    finally:
        sock.close()


# ── CCache file writer ────────────────────────────────────────────────

def _krb_time_to_unix(timestr: str) -> int:
    """Convert Kerberos GeneralizedTime string to Unix timestamp."""
    try:
        s = timestr.rstrip("Z")
        dt = datetime.strptime(s, "%Y%m%d%H%M%S")
        dt = dt.replace(tzinfo=timezone.utc)
        return int(dt.timestamp())
    except Exception:
        return int(time.time())


def _write_ccache(
    filepath: str,
    realm: str,
    client_principal: str,
    ticket_der: bytes,
    session_key_type: int,
    session_key: bytes,
    authtime: str,
    endtime: str,
    renew_till: str = "",
) -> None:
    """Write a MIT Kerberos ccache file (format version 0x0504).

    This produces a ccache file compatible with MIT krb5, Heimdal,
    and GSSAPI libraries.

    Args:
        filepath: Output file path.
        realm: Kerberos realm (e.g. 'CORP.LOCAL').
        client_principal: Client name (e.g. 'admin').
        ticket_der: DER-encoded Ticket (APPLICATION [1]).
        session_key_type: Encryption type of session key.
        session_key: Raw session key bytes.
        authtime: Auth time as GeneralizedTime string.
        endtime: End time as GeneralizedTime string.
        renew_till: Renew-till time as GeneralizedTime string.
    """
    realm_upper = realm.upper()

    def _cc_principal(name: str, realm_str: str) -> bytes:
        """Encode a ccache principal."""
        components = name.split("/")
        buf = struct.pack(">I", NT_PRINCIPAL)  # name_type
        buf += struct.pack(">I", len(components))  # num_components
        # Realm
        realm_bytes = realm_str.encode("ascii")
        buf += struct.pack(">I", len(realm_bytes)) + realm_bytes
        # Components
        for comp in components:
            comp_bytes = comp.encode("ascii")
            buf += struct.pack(">I", len(comp_bytes)) + comp_bytes
        return buf

    def _cc_credential() -> bytes:
        """Encode one ccache credential entry."""
        buf = b""
        # Client principal
        buf += _cc_principal(client_principal, realm_upper)
        # Server principal (krbtgt/REALM@REALM)
        buf += _cc_principal(f"krbtgt/{realm_upper}", realm_upper)

        # Keyblock: keytype(2) + etype(2) + keylen(2) + key
        # ccache v4 format: just keytype(4) + keylen(4) + key
        buf += struct.pack(">H", session_key_type)  # keytype (uint16 in v0504)
        buf += struct.pack(">H", session_key_type)  # etype (same)
        buf += struct.pack(">H", len(session_key))  # keylen
        buf += session_key

        # Times: authtime, starttime, endtime, renew_till (each uint32)
        auth_ts = _krb_time_to_unix(authtime)
        end_ts = _krb_time_to_unix(endtime)
        renew_ts = _krb_time_to_unix(renew_till) if renew_till else 0
        buf += struct.pack(">I", auth_ts)   # authtime
        buf += struct.pack(">I", auth_ts)   # starttime (same as auth)
        buf += struct.pack(">I", end_ts)    # endtime
        buf += struct.pack(">I", renew_ts)  # renew_till

        # is_skey (uint8)
        buf += b"\x00"

        # ticket_flags (uint32) — forwardable + renewable
        flags = KDC_OPT_FORWARDABLE | KDC_OPT_RENEWABLE
        buf += struct.pack(">I", flags)

        # Addresses (uint32 count = 0)
        buf += struct.pack(">I", 0)

        # Authdata (uint32 count = 0)
        buf += struct.pack(">I", 0)

        # Ticket (length-prefixed)
        buf += struct.pack(">I", len(ticket_der))
        buf += ticket_der

        # Second ticket (length-prefixed, empty)
        buf += struct.pack(">I", 0)

        return buf

    with open(filepath, "wb") as f:
        # File format version: 0x0504
        f.write(struct.pack(">H", 0x0504))

        # Header length (v0504 has a header section)
        # We write an empty header
        f.write(struct.pack(">H", 0))

        # Default principal
        f.write(_cc_principal(client_principal, realm_upper))

        # Credentials
        f.write(_cc_credential())

    log.info("Wrote ccache to %s", filepath)



# ── DC hostname resolution ────────────────────────────────────────────

def resolve_dc_hostname(dc_ip: str) -> str:
    """Resolve a DC IP to its hostname via reverse DNS.

    Kerberos requires the DC hostname for the SPN in the service ticket.
    This replaces impacket's SMB-based hostname resolution.

    Falls back to the IP if reverse DNS fails.
    """
    try:
        hostname, _, _ = socket.gethostbyaddr(dc_ip)
        log.info("Resolved DC %s → %s", dc_ip, hostname)
        return hostname
    except (socket.herror, socket.gaierror) as e:
        log.warning("Reverse DNS failed for %s: %s — using IP directly", dc_ip, e)
        return dc_ip


# ── Public API ────────────────────────────────────────────────────────

def get_tgt(
    dc_ip: str,
    domain: str,
    username: str,
    aes_key: str = "",
    nt_hash: str = "",
    timeout: int = 30,
) -> str:
    """Obtain a Kerberos TGT and write it to a ccache file.

    Sends an AS-REQ with encrypted timestamp pre-auth to the KDC,
    parses the AS-REP, and writes a standard MIT ccache file.
    Sets KRB5CCNAME environment variable to the ccache path.

    Args:
        dc_ip: Domain Controller IP or hostname (KDC).
        domain: Kerberos realm (e.g. 'CORP.LOCAL').
        username: Client principal name (e.g. 'admin').
        aes_key: Hex-encoded AES key (32 bytes for AES128, 64 for AES256).
        nt_hash: Hex-encoded NT hash (32 hex chars) for RC4-HMAC.
        timeout: Network timeout in seconds.

    Returns:
        Path to the ccache file.

    Raises:
        KerberosError: On authentication failure or protocol error.
        ValueError: On invalid parameters.
    """
    if not aes_key and not nt_hash:
        raise ValueError("Either aes_key or nt_hash must be provided")

    realm = domain.upper()

    # Determine etype and key
    if aes_key:
        key_bytes = bytes.fromhex(aes_key)
        if len(key_bytes) == 32:
            etype = ETYPE_AES256
        elif len(key_bytes) == 16:
            etype = ETYPE_AES128
        else:
            raise ValueError(
                f"AES key must be 16 bytes (AES128) or 32 bytes (AES256), "
                f"got {len(key_bytes)} bytes"
            )
        log.info("Using AES%d key for %s@%s",
                 256 if etype == ETYPE_AES256 else 128, username, realm)
    else:
        key_bytes = bytes.fromhex(nt_hash)
        if len(key_bytes) != 16:
            raise ValueError(
                f"NT hash must be 16 bytes (32 hex chars), got {len(key_bytes)}")
        etype = ETYPE_RC4_HMAC
        log.info("Using RC4-HMAC (NT hash) for %s@%s", username, realm)

    # Build AS-REQ
    as_req = _build_as_req(realm, username, key_bytes, etype)
    log.debug("Built AS-REQ (%d bytes) for %s@%s", len(as_req), username, realm)

    # Send to KDC
    log.info("Sending AS-REQ to %s:88", dc_ip)
    response = _send_kdc_request(dc_ip, as_req, timeout=timeout)
    log.debug("Received KDC response (%d bytes)", len(response))

    # Parse response
    parsed = _parse_as_rep(response)

    if parsed.get("msg_type") == KRB_ERROR:
        error_code = parsed.get("error_code", 0)
        e_text = parsed.get("e_text", "")
        # Map common error codes
        error_names = {
            6: "KDC_ERR_C_PRINCIPAL_UNKNOWN (client not found in database)",
            12: "KDC_ERR_POLICY (policy rejects request)",
            14: "KDC_ERR_ETYPE_NOSUPP (KDC has no support for encryption type)",
            18: "KDC_ERR_CLIENT_REVOKED (client credentials revoked)",
            24: "KDC_ERR_PREAUTH_FAILED (pre-authentication failed — wrong key?)",
            25: "KDC_ERR_PREAUTH_REQUIRED (pre-authentication required)",
        }
        error_name = error_names.get(error_code, f"error code {error_code}")
        raise KerberosError(
            f"KDC returned error: {error_name}"
            + (f" — {e_text}" if e_text else ""),
            error_code=error_code,
        )

    if parsed.get("msg_type") != KRB_AS_REP:
        raise KerberosError(
            f"Unexpected KDC response type: {parsed.get('msg_type')}")

    # Decrypt enc-part to get session key
    enc_etype = parsed.get("enc_etype", etype)
    cipher = parsed.get("enc_cipher", b"")
    if not cipher:
        raise KerberosError("AS-REP missing encrypted part")

    try:
        if enc_etype in (ETYPE_AES256, ETYPE_AES128):
            plaintext = aes_decrypt(key_bytes, KEY_USAGE_AS_REP_ENCPART, cipher)
        elif enc_etype == ETYPE_RC4_HMAC:
            plaintext = rc4_decrypt(key_bytes, 8, cipher)  # usage 8 for AS-REP
        else:
            raise KerberosError(f"Unsupported enc-part etype: {enc_etype}")
    except KerberosError:
        raise
    except Exception as e:
        raise KerberosError(f"Failed to decrypt AS-REP enc-part: {e}")

    # Parse decrypted EncASRepPart
    enc_rep = _parse_enc_as_rep_part(plaintext)

    session_key = enc_rep.get("key_value", b"")
    session_key_type = enc_rep.get("key_type", etype)
    authtime = enc_rep.get("authtime", "")
    endtime = enc_rep.get("endtime", "")
    renew_till = enc_rep.get("renew_till", "")

    if not session_key:
        raise KerberosError("Could not extract session key from AS-REP")

    # Get the raw ticket
    ticket_der = parsed.get("ticket_bytes", b"")
    if not ticket_der:
        raise KerberosError("Could not extract ticket from AS-REP")

    # Write ccache
    ccache_dir = tempfile.gettempdir()
    ccache_path = os.path.join(
        ccache_dir, f"krb5cc_netpal_{username}_{realm}")

    _write_ccache(
        filepath=ccache_path,
        realm=realm,
        client_principal=username,
        ticket_der=ticket_der,
        session_key_type=session_key_type,
        session_key=session_key,
        authtime=authtime,
        endtime=endtime,
        renew_till=renew_till,
    )

    # Set environment variable for GSSAPI
    os.environ["KRB5CCNAME"] = f"FILE:{ccache_path}"
    log.info("Set KRB5CCNAME=%s", os.environ["KRB5CCNAME"])

    return ccache_path


def check_crypto_available() -> bool:
    """Check if pycryptodome is available for Kerberos operations."""
    try:
        from Crypto.Cipher import AES, ARC4  # noqa: F401
        return True
    except ImportError:
        return False

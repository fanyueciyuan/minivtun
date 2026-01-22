# Encryption Design Issue and Solution

## Current Problem

### Message Structure
```
struct minivtun_msg {
    struct {
        __u8 opcode;           // offset 0
        __u8 rsv;              // offset 1
        __be16 seq;            // offset 2-3
        __u8 auth_key[16];     // offset 4-19
    } hdr;  // 20 bytes total

    union {
        struct { ... } ipdata;
        struct { ... } echo;
    };
}
```

### Current Flow (BROKEN)

**Client Send:**
1. Build message, header zeroed (including auth_key)
2. Encrypt ENTIRE message (header + payload) → ciphertext
3. Ciphertext now has encrypted data at offset 4-19 (auth_key field)
4. Zero out offset 4-19 in ciphertext ❌ **DESTROYS CIPHERTEXT**
5. Compute HMAC over (ciphertext with zeroed auth_key)
6. Write HMAC to offset 4-19
7. Send

**Server Receive:**
1. Receive: offset 4-19 contains HMAC, rest is ciphertext
2. Extract HMAC from offset 4-19
3. Zero offset 4-19
4. Compute HMAC, verify ✓
5. Try to restore ciphertext... **BUT WE DON'T HAVE IT!** ❌
6. Decrypt with corrupted ciphertext → **GARBAGE OUTPUT** ❌

### Why It Fails

In CBC mode, modifying ciphertext bytes affects decryption:
- Modifying block N affects decryption of block N and N+1
- auth_key is at offset 4-19 (spans block 0: bytes 0-15, and part of block 1)
- Losing those 16 bytes of ciphertext makes it impossible to correctly decrypt:
  - Block 0 (offset 0-15): contains opcode, rsv, seq, and part of auth_key
  - Decrypting with wrong data at offset 4-15 produces garbage opcode

**Result:** Server sees random opcodes like 0xf9, 0x4a, 0xd9 instead of 0x00 (ECHO_REQ)

## Solution Options

### Option 1: Don't Encrypt Header (RECOMMENDED)
- Encrypt only payload, not header
- Header (opcode, rsv, seq, auth_key) sent in plaintext
- HMAC covers entire message (header + encrypted payload)
- auth_key field purely for HMAC storage

**Pros:**
- Simple to implement
- No ciphertext loss
- Header fields (opcode, seq) available without decryption
- Standard practice for many protocols

**Cons:**
- Header metadata visible to attackers
- Sequence numbers visible (but not critical)

### Option 2: AEAD Mode (AES-GCM)
- Switch from AES-CBC to AES-GCM
- Supports Associated Data (header) that's authenticated but not encrypted
- Modern, secure approach

**Pros:**
- Best security
- Industry standard
- Built-in authentication

**Cons:**
- Requires OpenSSL 1.0.1+ or mbedTLS
- Larger code changes
- Different IV/nonce handling

### Option 3: Redesign Message Format
- Move auth_key outside encrypted region
- Requires protocol version bump
- Breaks compatibility

**Cons:**
- Most invasive change
- Compatibility issues

## Recommended Implementation: Option 1

### New Flow

**Client Send:**
1. Build message with header (opcode, rsv, seq, auth_key=0)
2. Encrypt ONLY payload (skip header) → encrypted_payload
3. Build final message: header (plaintext) + encrypted_payload
4. Zero auth_key field (it's already 0)
5. Compute HMAC over entire message
6. Write HMAC to auth_key field
7. Send

**Server Receive:**
1. Receive message
2. Extract HMAC from auth_key field
3. Zero auth_key field
4. Compute HMAC, verify ✓
5. No need to restore anything - header was never encrypted!
6. Decrypt payload only ✓
7. Process message with correct opcode ✓

### Code Changes Needed

1. Modify `crypto_encrypt()` and `crypto_decrypt()` to skip header:
   - Add parameter: `skip_header_bytes`
   - Encrypt/decrypt from offset `skip_header_bytes` onward

2. Update `local_to_netmsg()` and `netmsg_to_local()`:
   - Pass `MINIVTUN_MSG_BASIC_HLEN` as skip parameter
   - Only encrypt/decrypt payload portion

3. HMAC computation stays the same:
   - Still covers entire message (header + encrypted payload)
   - auth_key field zeroed during computation

### Security Analysis

- **Confidentiality:** Payload encrypted ✓
- **Integrity:** HMAC protects entire message ✓
- **Authenticity:** HMAC provides authentication ✓
- **Replay Protection:** Sequence number in header (could add timestamp)
- **Header Exposure:** Acceptable for this protocol (opcode, seq not sensitive)

## Next Steps

1. Implement Option 1 (skip header encryption)
2. Test with current infrastructure
3. Document protocol in README
4. Consider Option 2 (AES-GCM) for future version

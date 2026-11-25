///|
/// SM4 S-box (GB/T 32907-2016 §6.1).
let sbox : FixedArray[UInt32] = [
  0xd6U, 0x90U, 0xe9U, 0xfeU, 0xccU, 0xe1U, 0x3dU, 0xb7U, 0x16U, 0xb6U, 0x14U, 0xc2U,
  0x28U, 0xfbU, 0x2cU, 0x05U, 0x2bU, 0x67U, 0x9aU, 0x76U, 0x2aU, 0xbeU, 0x04U, 0xc3U,
  0xaaU, 0x44U, 0x13U, 0x26U, 0x49U, 0x86U, 0x06U, 0x99U, 0x9cU, 0x42U, 0x50U, 0xf4U,
  0x91U, 0xefU, 0x98U, 0x7aU, 0x33U, 0x54U, 0x0bU, 0x43U, 0xedU, 0xcfU, 0xacU, 0x62U,
  0xe4U, 0xb3U, 0x1cU, 0xa9U, 0xc9U, 0x08U, 0xe8U, 0x95U, 0x80U, 0xdfU, 0x94U, 0xfaU,
  0x75U, 0x8fU, 0x3fU, 0xa6U, 0x47U, 0x07U, 0xa7U, 0xfcU, 0xf3U, 0x73U, 0x17U, 0xbaU,
  0x83U, 0x59U, 0x3cU, 0x19U, 0xe6U, 0x85U, 0x4fU, 0xa8U, 0x68U, 0x6bU, 0x81U, 0xb2U,
  0x71U, 0x64U, 0xdaU, 0x8bU, 0xf8U, 0xebU, 0x0fU, 0x4bU, 0x70U, 0x56U, 0x9dU, 0x35U,
  0x1eU, 0x24U, 0x0eU, 0x5eU, 0x63U, 0x58U, 0xd1U, 0xa2U, 0x25U, 0x22U, 0x7cU, 0x3bU,
  0x01U, 0x21U, 0x78U, 0x87U, 0xd4U, 0x00U, 0x46U, 0x57U, 0x9fU, 0xd3U, 0x27U, 0x52U,
  0x4cU, 0x36U, 0x02U, 0xe7U, 0xa0U, 0xc4U, 0xc8U, 0x9eU, 0xeaU, 0xbfU, 0x8aU, 0xd2U,
  0x40U, 0xc7U, 0x38U, 0xb5U, 0xa3U, 0xf7U, 0xf2U, 0xceU, 0xf9U, 0x61U, 0x15U, 0xa1U,
  0xe0U, 0xaeU, 0x5dU, 0xa4U, 0x9bU, 0x34U, 0x1aU, 0x55U, 0xadU, 0x93U, 0x32U, 0x30U,
  0xf5U, 0x8cU, 0xb1U, 0xe3U, 0x1dU, 0xf6U, 0xe2U, 0x2eU, 0x82U, 0x66U, 0xcaU, 0x60U,
  0xc0U, 0x29U, 0x23U, 0xabU, 0x0dU, 0x53U, 0x4eU, 0x6fU, 0xd5U, 0xdbU, 0x37U, 0x45U,
  0xdeU, 0xfdU, 0x8eU, 0x2fU, 0x03U, 0xffU, 0x6aU, 0x72U, 0x6dU, 0x6cU, 0x5bU, 0x51U,
  0x8dU, 0x1bU, 0xafU, 0x92U, 0xbbU, 0xddU, 0xbcU, 0x7fU, 0x11U, 0xd9U, 0x5cU, 0x41U,
  0x1fU, 0x10U, 0x5aU, 0xd8U, 0x0aU, 0xc1U, 0x31U, 0x88U, 0xa5U, 0xcdU, 0x7bU, 0xbdU,
  0x2dU, 0x74U, 0xd0U, 0x12U, 0xb8U, 0xe5U, 0xb4U, 0xb0U, 0x89U, 0x69U, 0x97U, 0x4aU,
  0x0cU, 0x96U, 0x77U, 0x7eU, 0x65U, 0xb9U, 0xf1U, 0x09U, 0xc5U, 0x6eU, 0xc6U, 0x84U,
  0x18U, 0xf0U, 0x7dU, 0xecU, 0x3aU, 0xdcU, 0x4dU, 0x20U, 0x79U, 0xeeU, 0x5fU, 0x3eU,
  0xd7U, 0xcbU, 0x39U, 0x48U,
]

///|
/// SM4 system parameters FK (GB/T 32907-2016 §7.3.1).
let fk0 : UInt32 = 0xa3b1bac6U

///|
let fk1 : UInt32 = 0x56aa3350U

///|
let fk2 : UInt32 = 0x677d9197U

///|
let fk3 : UInt32 = 0xb27022dcU

///|
/// SM4 fixed key expansion constants CK[0..31] (GB/T 32907-2016 §7.3.2).
let ck : FixedArray[UInt32] = [
  0x00070e15U, 0x1c232a31U, 0x383f464dU, 0x545b6269U, 0x70777e85U, 0x8c939aa1U, 0xa8afb6bdU,
  0xc4cbd2d9U, 0xe0e7eef5U, 0xfc030a11U, 0x181f262dU, 0x343b4249U, 0x50575e65U, 0x6c737a81U,
  0x888f969dU, 0xa4abb2b9U, 0xc0c7ced5U, 0xdce3eaf1U, 0xf8ff060dU, 0x141b2229U, 0x30373e45U,
  0x4c535a61U, 0x686f767dU, 0x848b9299U, 0xa0a7aeb5U, 0xbcc3cad1U, 0xd8dfe6edU, 0xf4fb0209U,
  0x10171e25U, 0x2c333a41U, 0x484f565dU, 0x646b7279U,
]

///|
/// Expanded SM4 key schedule holding 32 round keys (GB/T 32907-2016).
pub struct Sm4Key {
  priv rk : FixedArray[UInt32]
}

///|
fn rotl32(x : UInt32, n : Int32) -> UInt32 {
  (x << n) | (x >> (32 - n))
}

///|
fn tau(a : UInt32) -> UInt32 {
  let b0 = sbox[(a >> 24).reinterpret_as_int()]
  let b1 = sbox[((a >> 16) & 0xffU).reinterpret_as_int()]
  let b2 = sbox[((a >> 8) & 0xffU).reinterpret_as_int()]
  let b3 = sbox[(a & 0xffU).reinterpret_as_int()]
  (b0 << 24) | (b1 << 16) | (b2 << 8) | b3
}

///|
fn t_round(x : UInt32) -> UInt32 {
  let b = tau(x)
  b ^ rotl32(b, 2) ^ rotl32(b, 10) ^ rotl32(b, 18) ^ rotl32(b, 24)
}

///|
fn t_key(x : UInt32) -> UInt32 {
  let b = tau(x)
  b ^ rotl32(b, 13) ^ rotl32(b, 23)
}

///|
fn read_be_u32_view(buf : BytesView, off : Int32) -> UInt32 {
  (buf[off].to_uint() << 24) |
  (buf[off + 1].to_uint() << 16) |
  (buf[off + 2].to_uint() << 8) |
  buf[off + 3].to_uint()
}

///|
fn read_be_u32_fixed(buf : FixedArray[Byte], off : Int32) -> UInt32 {
  (buf[off].to_uint() << 24) |
  (buf[off + 1].to_uint() << 16) |
  (buf[off + 2].to_uint() << 8) |
  buf[off + 3].to_uint()
}

///|
fn write_be_u32(out : FixedArray[Byte], off : Int32, v : UInt32) -> Unit {
  out[off] = (v >> 24).to_byte()
  out[off + 1] = (v >> 16).to_byte()
  out[off + 2] = (v >> 8).to_byte()
  out[off + 3] = v.to_byte()
}

///|
/// Creates an expanded SM4 key schedule from a 16-byte key.
/// Returns `None` if `key.length() != 16`.
pub fn Sm4Key::new(key : BytesView) -> Sm4Key? {
  if key.length() != 16 {
    return None
  }
  let mut k0 = read_be_u32_view(key, 0) ^ fk0
  let mut k1 = read_be_u32_view(key, 4) ^ fk1
  let mut k2 = read_be_u32_view(key, 8) ^ fk2
  let mut k3 = read_be_u32_view(key, 12) ^ fk3
  let rk : FixedArray[UInt32] = FixedArray::make(32, 0U)
  for i = 0; i < 32; i = i + 1 {
    let next = k0 ^ t_key(k1 ^ k2 ^ k3 ^ ck[i])
    rk[i] = next
    k0 = k1
    k1 = k2
    k2 = k3
    k3 = next
  }
  Some({ rk, })
}

///|
fn Sm4Key::encrypt_words_into(
  self : Sm4Key,
  w0 : UInt32,
  w1 : UInt32,
  w2 : UInt32,
  w3 : UInt32,
  out : FixedArray[Byte],
  out_off : Int32,
) -> Unit {
  let mut x0 = w0
  let mut x1 = w1
  let mut x2 = w2
  let mut x3 = w3
  for i = 0; i < 32; i = i + 1 {
    let next = x0 ^ t_round(x1 ^ x2 ^ x3 ^ self.rk[i])
    x0 = x1
    x1 = x2
    x2 = x3
    x3 = next
  }
  write_be_u32(out, out_off, x3)
  write_be_u32(out, out_off + 4, x2)
  write_be_u32(out, out_off + 8, x1)
  write_be_u32(out, out_off + 12, x0)
}

///|
fn Sm4Key::decrypt_words_into(
  self : Sm4Key,
  w0 : UInt32,
  w1 : UInt32,
  w2 : UInt32,
  w3 : UInt32,
  out : FixedArray[Byte],
  out_off : Int32,
) -> Unit {
  let mut x0 = w0
  let mut x1 = w1
  let mut x2 = w2
  let mut x3 = w3
  for i = 31; i >= 0; i = i - 1 {
    let next = x0 ^ t_round(x1 ^ x2 ^ x3 ^ self.rk[i])
    x0 = x1
    x1 = x2
    x2 = x3
    x3 = next
  }
  write_be_u32(out, out_off, x3)
  write_be_u32(out, out_off + 4, x2)
  write_be_u32(out, out_off + 8, x1)
  write_be_u32(out, out_off + 12, x0)
}

///|
/// Encrypts a single 16-byte block with SM4.
/// Returns `None` if `block.length() != 16`.
pub fn Sm4Key::encrypt_block(self : Sm4Key, block : BytesView) -> Bytes? {
  if block.length() != 16 {
    return None
  }
  let out : FixedArray[Byte] = FixedArray::make(16, b'\x00')
  self.encrypt_words_into(
    read_be_u32_view(block, 0),
    read_be_u32_view(block, 4),
    read_be_u32_view(block, 8),
    read_be_u32_view(block, 12),
    out,
    0,
  )
  Some(Bytes::makei(16, fn(i) { out[i] }))
}

///|
/// Decrypts a single 16-byte block with SM4.
/// Returns `None` if `block.length() != 16`.
pub fn Sm4Key::decrypt_block(self : Sm4Key, block : BytesView) -> Bytes? {
  if block.length() != 16 {
    return None
  }
  let out : FixedArray[Byte] = FixedArray::make(16, b'\x00')
  self.decrypt_words_into(
    read_be_u32_view(block, 0),
    read_be_u32_view(block, 4),
    read_be_u32_view(block, 8),
    read_be_u32_view(block, 12),
    out,
    0,
  )
  Some(Bytes::makei(16, fn(i) { out[i] }))
}

///|
/// Encrypts `plaintext` using SM4-ECB with PKCS#7 padding (1..16 bytes).
/// Returns `None` if `key.length() != 16`.
pub fn encrypt_ecb_pkcs7(key : BytesView, plaintext : BytesView) -> Bytes? {
  let sm4 = match Sm4Key::new(key) {
    Some(k) => k
    None => return None
  }
  let plen = plaintext.length()
  let rem = plen % 16
  let full_bytes = plen - rem
  let pad_len = 16 - rem
  let total_len = plen + pad_len
  let out : FixedArray[Byte] = FixedArray::make(total_len, b'\x00')
  let mut off = 0
  while off < full_bytes {
    sm4.encrypt_words_into(
      read_be_u32_view(plaintext, off),
      read_be_u32_view(plaintext, off + 4),
      read_be_u32_view(plaintext, off + 8),
      read_be_u32_view(plaintext, off + 12),
      out,
      off,
    )
    off = off + 16
  }
  let last_block : FixedArray[Byte] = FixedArray::make(16, pad_len.to_byte())
  for i = 0; i < rem; i = i + 1 {
    last_block[i] = plaintext[full_bytes + i]
  }
  sm4.encrypt_words_into(
    read_be_u32_fixed(last_block, 0),
    read_be_u32_fixed(last_block, 4),
    read_be_u32_fixed(last_block, 8),
    read_be_u32_fixed(last_block, 12),
    out,
    full_bytes,
  )
  Some(Bytes::makei(total_len, fn(i) { out[i] }))
}

///|
/// Decrypts `ciphertext` using SM4-ECB and strictly validates/removes PKCS#7 padding.
/// Returns `None` if `key.length() != 16`, `ciphertext` is empty or not a multiple of 16 bytes,
/// or any PKCS#7 padding byte is invalid.
pub fn decrypt_ecb_pkcs7(key : BytesView, ciphertext : BytesView) -> Bytes? {
  let sm4 = match Sm4Key::new(key) {
    Some(k) => k
    None => return None
  }
  let clen = ciphertext.length()
  if clen == 0 || clen % 16 != 0 {
    return None
  }
  let plain : FixedArray[Byte] = FixedArray::make(clen, b'\x00')
  let mut off = 0
  while off < clen {
    sm4.decrypt_words_into(
      read_be_u32_view(ciphertext, off),
      read_be_u32_view(ciphertext, off + 4),
      read_be_u32_view(ciphertext, off + 8),
      read_be_u32_view(ciphertext, off + 12),
      plain,
      off,
    )
    off = off + 16
  }
  // Constant-time strict PKCS#7 padding validation over the final 16-byte block.
  let pad = plain[clen - 1].to_int()
  let mut bad = ((pad - 1).reinterpret_as_uint() >> 31) |
    ((16 - pad).reinterpret_as_uint() >> 31)
  for i = 0; i < 16; i = i + 1 {
    let in_pad = (i - pad).reinterpret_as_uint() >> 31
    let mask = 0U - in_pad
    let diff = (plain[clen - 1 - i].to_int() ^ pad).reinterpret_as_uint()
    bad = bad | (diff & mask)
  }
  if bad != 0U {
    return None
  }
  let out_len = clen - pad
  Some(Bytes::makei(out_len, fn(i) { plain[i] }))
}

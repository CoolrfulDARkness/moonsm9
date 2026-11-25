///|
/// SM3 initial hash values (GB/T 32905-2016 §4.1).
let iv0 : UInt32 = 0x7380166FU

///|
let iv1 : UInt32 = 0x4914B2B9U

///|
let iv2 : UInt32 = 0x172442D7U

///|
let iv3 : UInt32 = 0xDA8A0600U

///|
let iv4 : UInt32 = 0xA96F30BCU

///|
let iv5 : UInt32 = 0x163138AAU

///|
let iv6 : UInt32 = 0xE38DEE4DU

///|
let iv7 : UInt32 = 0xB0FB0E4EU

///|
/// Precomputed `rotl32(T_j, j mod 32)` for j = 0..63 (GB/T 32905-2016 §4.2).
let tj_rotl : FixedArray[UInt32] = [
  0x79CC4519U, 0xF3988A32U, 0xE7311465U, 0xCE6228CBU, 0x9CC45197U, 0x3988A32FU, 0x7311465EU,
  0xE6228CBCU, 0xCC451979U, 0x988A32F3U, 0x311465E7U, 0x6228CBCEU, 0xC451979CU, 0x88A32F39U,
  0x11465E73U, 0x228CBCE6U, 0x9D8A7A87U, 0x3B14F50FU, 0x7629EA1EU, 0xEC53D43CU, 0xD8A7A879U,
  0xB14F50F3U, 0x629EA1E7U, 0xC53D43CEU, 0x8A7A879DU, 0x14F50F3BU, 0x29EA1E76U, 0x53D43CECU,
  0xA7A879D8U, 0x4F50F3B1U, 0x9EA1E762U, 0x3D43CEC5U, 0x7A879D8AU, 0xF50F3B14U, 0xEA1E7629U,
  0xD43CEC53U, 0xA879D8A7U, 0x50F3B14FU, 0xA1E7629EU, 0x43CEC53DU, 0x879D8A7AU, 0x0F3B14F5U,
  0x1E7629EAU, 0x3CEC53D4U, 0x79D8A7A8U, 0xF3B14F50U, 0xE7629EA1U, 0xCEC53D43U, 0x9D8A7A87U,
  0x3B14F50FU, 0x7629EA1EU, 0xEC53D43CU, 0xD8A7A879U, 0xB14F50F3U, 0x629EA1E7U, 0xC53D43CEU,
  0x8A7A879DU, 0x14F50F3BU, 0x29EA1E76U, 0x53D43CECU, 0xA7A879D8U, 0x4F50F3B1U, 0x9EA1E762U,
  0x3D43CEC5U,
]

///|
/// Streaming SM3 hash state (GB/T 32905-2016).
pub struct Sm3 {
  priv state : FixedArray[UInt32]
  priv buf : FixedArray[Byte]
  priv mut buf_len : Int32
  priv mut bit_len : UInt64
}

///|
fn rotl32(x : UInt32, n : Int32) -> UInt32 {
  (x << n) | (x >> (32 - n))
}

///|
fn p0(x : UInt32) -> UInt32 {
  x ^ rotl32(x, 9) ^ rotl32(x, 17)
}

///|
fn p1(x : UInt32) -> UInt32 {
  x ^ rotl32(x, 15) ^ rotl32(x, 23)
}

///|
fn read_be_u32_fixed(buf : FixedArray[Byte], off : Int32) -> UInt32 {
  (buf[off].to_uint() << 24) |
  (buf[off + 1].to_uint() << 16) |
  (buf[off + 2].to_uint() << 8) |
  buf[off + 3].to_uint()
}

///|
fn read_be_u32_view(buf : BytesView, off : Int32) -> UInt32 {
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
fn read_be_u64_view(buf : BytesView, off : Int32) -> UInt64 {
  (buf[off].to_uint64() << 56) |
  (buf[off + 1].to_uint64() << 48) |
  (buf[off + 2].to_uint64() << 40) |
  (buf[off + 3].to_uint64() << 32) |
  (buf[off + 4].to_uint64() << 24) |
  (buf[off + 5].to_uint64() << 16) |
  (buf[off + 6].to_uint64() << 8) |
  buf[off + 7].to_uint64()
}

///|
fn write_be_u64(out : FixedArray[Byte], off : Int32, v : UInt64) -> Unit {
  out[off] = (v >> 56).to_byte()
  out[off + 1] = (v >> 48).to_byte()
  out[off + 2] = (v >> 40).to_byte()
  out[off + 3] = (v >> 32).to_byte()
  out[off + 4] = (v >> 24).to_byte()
  out[off + 5] = (v >> 16).to_byte()
  out[off + 6] = (v >> 8).to_byte()
  out[off + 7] = v.to_byte()
}

///|
fn compress_words(state : FixedArray[UInt32], w : FixedArray[UInt32]) -> Unit {
  for j = 16; j < 68; j = j + 1 {
    let x = w[j - 16] ^ w[j - 9] ^ rotl32(w[j - 3], 15)
    w[j] = p1(x) ^ rotl32(w[j - 13], 7) ^ w[j - 6]
  }
  let mut a = state[0]
  let mut b = state[1]
  let mut c = state[2]
  let mut d = state[3]
  let mut e = state[4]
  let mut f = state[5]
  let mut g = state[6]
  let mut h = state[7]
  for j = 0; j < 16; j = j + 1 {
    let a12 = rotl32(a, 12)
    let ss1 = rotl32(a12 + e + tj_rotl[j], 7)
    let ss2 = ss1 ^ a12
    let tt1 = (a ^ b ^ c) + d + ss2 + (w[j] ^ w[j + 4])
    let tt2 = (e ^ f ^ g) + h + ss1 + w[j]
    d = c
    c = rotl32(b, 9)
    b = a
    a = tt1
    h = g
    g = rotl32(f, 19)
    f = e
    e = p0(tt2)
  }
  for j = 16; j < 64; j = j + 1 {
    let a12 = rotl32(a, 12)
    let ss1 = rotl32(a12 + e + tj_rotl[j], 7)
    let ss2 = ss1 ^ a12
    let ff = (a & b) | (a & c) | (b & c)
    let gg = (e & f) | (e.lnot() & g)
    let tt1 = ff + d + ss2 + (w[j] ^ w[j + 4])
    let tt2 = gg + h + ss1 + w[j]
    d = c
    c = rotl32(b, 9)
    b = a
    a = tt1
    h = g
    g = rotl32(f, 19)
    f = e
    e = p0(tt2)
  }
  state[0] = state[0] ^ a
  state[1] = state[1] ^ b
  state[2] = state[2] ^ c
  state[3] = state[3] ^ d
  state[4] = state[4] ^ e
  state[5] = state[5] ^ f
  state[6] = state[6] ^ g
  state[7] = state[7] ^ h
}

///|
fn compress_block_fixed(
  state : FixedArray[UInt32],
  block : FixedArray[Byte],
) -> Unit {
  let w : FixedArray[UInt32] = FixedArray::make(68, 0U)
  for i = 0; i < 16; i = i + 1 {
    w[i] = read_be_u32_fixed(block, i * 4)
  }
  compress_words(state, w)
}

///|
fn compress_block_view(
  state : FixedArray[UInt32],
  data : BytesView,
  off : Int32,
) -> Unit {
  let w : FixedArray[UInt32] = FixedArray::make(68, 0U)
  for i = 0; i < 16; i = i + 1 {
    w[i] = read_be_u32_view(data, off + i * 4)
  }
  compress_words(state, w)
}

///|
/// Creates a new SM3 hasher initialized to the standard IV.
pub fn Sm3::new() -> Sm3 {
  {
    state: [iv0, iv1, iv2, iv3, iv4, iv5, iv6, iv7],
    buf: FixedArray::make(64, b'\x00'),
    buf_len: 0,
    bit_len: 0UL,
  }
}

///|
/// Resets the SM3 hasher back to its initial state.
pub fn Sm3::reset(self : Sm3) -> Unit {
  self.state[0] = iv0
  self.state[1] = iv1
  self.state[2] = iv2
  self.state[3] = iv3
  self.state[4] = iv4
  self.state[5] = iv5
  self.state[6] = iv6
  self.state[7] = iv7
  for i = 0; i < 64; i = i + 1 {
    self.buf[i] = b'\x00'
  }
  self.buf_len = 0
  self.bit_len = 0UL
}

///|
fn Sm3::clone(self : Sm3) -> Sm3 {
  let state : FixedArray[UInt32] = [
    self.state[0],
    self.state[1],
    self.state[2],
    self.state[3],
    self.state[4],
    self.state[5],
    self.state[6],
    self.state[7],
  ]
  let buf : FixedArray[Byte] = FixedArray::make(64, b'\x00')
  for i = 0; i < self.buf_len; i = i + 1 {
    buf[i] = self.buf[i]
  }
  { state, buf, buf_len: self.buf_len, bit_len: self.bit_len, }
}

///|
/// Absorbs a single byte into the SM3 state.
pub fn Sm3::update_byte(self : Sm3, b : Byte) -> Unit {
  self.buf[self.buf_len] = b
  self.buf_len = self.buf_len + 1
  self.bit_len = self.bit_len + 8UL
  if self.buf_len == 64 {
    compress_block_fixed(self.state, self.buf)
    self.buf_len = 0
  }
}

///|
/// Absorbs a byte slice into the SM3 state.
pub fn Sm3::update(self : Sm3, data : BytesView) -> Unit {
  let len = data.length()
  if len == 0 {
    return
  }
  self.bit_len = self.bit_len + (len.to_uint64() << 3)
  let mut off = 0
  if self.buf_len > 0 {
    let need = 64 - self.buf_len
    if len < need {
      for i = 0; i < len; i = i + 1 {
        self.buf[self.buf_len + i] = data[i]
      }
      self.buf_len = self.buf_len + len
      return
    }
    for i = 0; i < need; i = i + 1 {
      self.buf[self.buf_len + i] = data[i]
    }
    compress_block_fixed(self.state, self.buf)
    self.buf_len = 0
    off = need
  }
  while len - off >= 64 {
    compress_block_view(self.state, data, off)
    off = off + 64
  }
  let rem = len - off
  if rem > 0 {
    for i = 0; i < rem; i = i + 1 {
      self.buf[i] = data[off + i]
    }
    self.buf_len = rem
  }
}

///|
fn Sm3::update_be_u32(self : Sm3, v : UInt32) -> Unit {
  self.update_byte((v >> 24).to_byte())
  self.update_byte((v >> 16).to_byte())
  self.update_byte((v >> 8).to_byte())
  self.update_byte(v.to_byte())
}

///|
/// Finalizes the SM3 digest and returns the 32-byte hash without mutating `self`.
pub fn Sm3::finalize(self : Sm3) -> Bytes {
  let state : FixedArray[UInt32] = [
    self.state[0],
    self.state[1],
    self.state[2],
    self.state[3],
    self.state[4],
    self.state[5],
    self.state[6],
    self.state[7],
  ]
  let block : FixedArray[Byte] = FixedArray::make(64, b'\x00')
  let mut pos = self.buf_len
  for i = 0; i < pos; i = i + 1 {
    block[i] = self.buf[i]
  }
  block[pos] = b'\x80'
  pos = pos + 1
  if pos > 56 {
    for i = pos; i < 64; i = i + 1 {
      block[i] = b'\x00'
    }
    compress_block_fixed(state, block)
    for i = 0; i < 56; i = i + 1 {
      block[i] = b'\x00'
    }
  } else {
    for i = pos; i < 56; i = i + 1 {
      block[i] = b'\x00'
    }
  }
  write_be_u64(block, 56, self.bit_len)
  compress_block_fixed(state, block)
  let out : FixedArray[Byte] = FixedArray::make(32, b'\x00')
  for i = 0; i < 8; i = i + 1 {
    write_be_u32(out, i * 4, state[i])
  }
  Bytes::makei(32, fn(i) { out[i] })
}

///|
/// Computes the 32-byte SM3 digest of `data`.
pub fn hash(data : BytesView) -> Bytes {
  let hasher = Sm3::new()
  hasher.update(data)
  hasher.finalize()
}

///|
/// Computes the 64-character lowercase hex SM3 digest of `data`.
pub fn hash_hex(data : BytesView) -> String {
  bytes_to_hex(hash(data))
}

///|
/// Key derivation function `KDF(Z, klen)` (GB/T 38635.1-2020 §5.4.3).
/// `klen` is in bytes; returns empty `Bytes` if `klen <= 0`.
pub fn kdf(z : BytesView, klen : Int32) -> Bytes {
  if klen <= 0 {
    return b""
  }
  let base = Sm3::new()
  base.update(z)
  let out : FixedArray[Byte] = FixedArray::make(klen, b'\x00')
  let mut offset = 0
  let mut ct : UInt32 = 1U
  while offset < klen {
    let h = base.clone()
    h.update_be_u32(ct)
    let block = h.finalize()
    let take = if klen - offset < 32 { klen - offset } else { 32 }
    for i = 0; i < take; i = i + 1 {
      out[offset + i] = block[i]
    }
    offset = offset + take
    ct = ct + 1U
  }
  Bytes::makei(klen, fn(i) { out[i] })
}

///|
/// Message authentication code `MAC(K2, C2) = SM3(C2 || K2)` (GB/T 38635.4-2020).
pub fn mac(k2 : BytesView, c2 : BytesView) -> Bytes {
  let hasher = Sm3::new()
  hasher.update(c2)
  hasher.update(k2)
  hasher.finalize()
}

///|
/// Auxiliary hash-expansion function `Hv` returning `out_len` bytes of
/// `SM3(tag || Z || ct)` for `ct = 1, 2, ...` (GB/T 38635.1-2020 §5.4.2).
pub fn hv_bytes(tag : Byte, z : BytesView, out_len : Int32) -> Bytes {
  if out_len <= 0 {
    return b""
  }
  let base = Sm3::new()
  base.update_byte(tag)
  base.update(z)
  let out : FixedArray[Byte] = FixedArray::make(out_len, b'\x00')
  let mut offset = 0
  let mut ct : UInt32 = 1U
  while offset < out_len {
    let h = base.clone()
    h.update_be_u32(ct)
    let block = h.finalize()
    let take = if out_len - offset < 32 { out_len - offset } else { 32 }
    for i = 0; i < take; i = i + 1 {
      out[offset + i] = block[i]
    }
    offset = offset + take
    ct = ct + 1U
  }
  Bytes::makei(out_len, fn(i) { out[i] })
}

///|
/// Computes the 40-byte raw expansion `Ha` for SM9 `H1` (`tag = 0x01`).
pub fn h1_hash40(z : BytesView) -> Bytes {
  hv_bytes(b'\x01', z, 40)
}

///|
/// Computes the 40-byte raw expansion `Ha` for SM9 `H2` (`tag = 0x02`).
pub fn h2_hash40(z : BytesView) -> Bytes {
  hv_bytes(b'\x02', z, 40)
}

///|
/// Branchless unsigned 64-bit less-than returning `1UL` if `a < b`, else `0UL`.
fn lt_u64(a : UInt64, b : UInt64) -> UInt64 {
  ((a.lnot() & b) | ((a ^ b).lnot() & (a - b))) >> 63
}

///|
/// Constant-time exact big-integer reduction: `(ha mod (n - 1)) + 1`
/// where `ha` is 40-byte big-endian unsigned integer and `n_be` is 32-byte big-endian (`n > 1`).
fn reduce_ha40_mod_n_minus_1_plus_1(ha : Bytes, n_be : BytesView) -> Bytes {
  if n_be.length() != 32 {
    abort("sm3: n_be must be 32 bytes")
  }
  let n3 = read_be_u64_view(n_be, 0)
  let n2 = read_be_u64_view(n_be, 8)
  let n1 = read_be_u64_view(n_be, 16)
  let n0 = read_be_u64_view(n_be, 24)
  if n3 == 0UL && n2 == 0UL && n1 == 0UL && n0 <= 1UL {
    abort("sm3: group order n must be greater than 1")
  }
  // m = n - 1 (256-bit little-endian limbs m0..m3)
  let m0 = n0 - 1UL
  let bm0 = lt_u64(n0, 1UL)
  let m1 = n1 - bm0
  let bm1 = lt_u64(n1, bm0)
  let m2 = n2 - bm1
  let bm2 = lt_u64(n2, bm1)
  let m3 = n3 - bm2
  // 257-bit remainder (r4, r3, r2, r1, r0), processing 320 bits of ha MSB-first.
  let mut r0 = 0UL
  let mut r1 = 0UL
  let mut r2 = 0UL
  let mut r3 = 0UL
  let mut r4 = 0UL
  for byte_idx = 0; byte_idx < 40; byte_idx = byte_idx + 1 {
    let b = ha[byte_idx].to_int()
    for shift = 7; shift >= 0; shift = shift - 1 {
      let bit = ((b >> shift) & 1).to_uint64()
      r4 = (r4 << 1) | (r3 >> 63)
      r3 = (r3 << 1) | (r2 >> 63)
      r2 = (r2 << 1) | (r1 >> 63)
      r1 = (r1 << 1) | (r0 >> 63)
      r0 = (r0 << 1) | bit
      // Trial subtraction: t = r - m
      let t0 = r0 - m0
      let b0 = lt_u64(r0, m0)
      let t1_a = r1 - m1
      let b1_a = lt_u64(r1, m1)
      let t1 = t1_a - b0
      let b1 = b1_a | lt_u64(t1_a, b0)
      let t2_a = r2 - m2
      let b2_a = lt_u64(r2, m2)
      let t2 = t2_a - b1
      let b2 = b2_a | lt_u64(t2_a, b1)
      let t3_a = r3 - m3
      let b3_a = lt_u64(r3, m3)
      let t3 = t3_a - b2
      let b3 = b3_a | lt_u64(t3_a, b2)
      let t4 = r4 - b3
      let underflow = lt_u64(r4, b3)
      // Select r if underflow == 1, else t (constant-time)
      let mask = 0UL - underflow
      r0 = t0 ^ ((t0 ^ r0) & mask)
      r1 = t1 ^ ((t1 ^ r1) & mask)
      r2 = t2 ^ ((t2 ^ r2) & mask)
      r3 = t3 ^ ((t3 ^ r3) & mask)
      r4 = t4 ^ ((t4 ^ r4) & mask)
    }
  }
  // h = r + 1
  let s0 = r0 + 1UL
  let c0 = lt_u64(s0, 1UL)
  let s1 = r1 + c0
  let c1 = lt_u64(s1, c0)
  let s2 = r2 + c1
  let c2 = lt_u64(s2, c1)
  let s3 = r3 + c2
  let out : FixedArray[Byte] = FixedArray::make(32, b'\x00')
  write_be_u64(out, 0, s3)
  write_be_u64(out, 8, s2)
  write_be_u64(out, 16, s1)
  write_be_u64(out, 24, s0)
  Bytes::makei(32, fn(i) { out[i] })
}

///|
/// Cryptographic function `H1(Z, n)` returning a 32-byte big-endian scalar in `[1, n - 1]`
/// (GB/T 38635.1-2020 §5.4.2.2).
pub fn h1(z : BytesView, n_be : BytesView) -> Bytes {
  reduce_ha40_mod_n_minus_1_plus_1(h1_hash40(z), n_be)
}

///|
/// Cryptographic function `H2(Z, n)` returning a 32-byte big-endian scalar in `[1, n - 1]`
/// (GB/T 38635.1-2020 §5.4.2.3).
pub fn h2(z : BytesView, n_be : BytesView) -> Bytes {
  reduce_ha40_mod_n_minus_1_plus_1(h2_hash40(z), n_be)
}

///|
/// Constant-time byte slice equality check.
pub fn ct_eq_bytes(a : BytesView, b : BytesView) -> Bool {
  if a.length() != b.length() {
    return false
  }
  let mut diff = 0
  for i = 0; i < a.length(); i = i + 1 {
    diff = diff | (a[i].to_int() ^ b[i].to_int())
  }
  diff == 0
}

///|
let hex_digits : FixedArray[Char] = [
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
]

///|
/// Encodes bytes into a lowercase hexadecimal string.
pub fn bytes_to_hex(data : BytesView) -> String {
  let sb = StringBuilder(capacity=data.length() * 2)
  for i = 0; i < data.length(); i = i + 1 {
    let v = data[i].to_int()
    sb.write_char(hex_digits[(v >> 4) & 0xF])
    sb.write_char(hex_digits[v & 0xF])
  }
  sb.to_string()
}

///|
/// Decodes a hexadecimal string (case-insensitive, ignoring ASCII whitespace) into `Bytes`.
/// Returns `None` on invalid characters or odd number of hex digits.
pub fn hex_to_bytes(hex : String) -> Bytes? {
  let out : Array[Byte] = []
  let mut have_high = false
  let mut high = 0
  for c in hex {
    if c == ' ' || c == '\t' || c == '\r' || c == '\n' {
      continue
    }
    let v = match c {
      '0'..<='9' => c.to_int() - '0'.to_int()
      'a'..<='f' => c.to_int() - 'a'.to_int() + 10
      'A'..<='F' => c.to_int() - 'A'.to_int() + 10
      _ => return None
    }
    if have_high {
      out.push(((high << 4) | v).to_byte())
      have_high = false
    } else {
      high = v
      have_high = true
    }
  }
  if have_high {
    return None
  }
  Some(Bytes::from_array(out))
}

///|
fn hex_to_bytes(hex : String) -> Bytes {
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
      _ => abort("invalid hex char in test vector")
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
    abort("odd hex length in test vector")
  }
  Bytes::from_array(out)
}

///|
fn bytes_to_hex(data : BytesView) -> String {
  let digits : FixedArray[Char] = [
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
  ]
  let sb = StringBuilder(capacity=data.length() * 2)
  for i = 0; i < data.length(); i = i + 1 {
    let v = data[i].to_int()
    sb.write_char(digits[(v >> 4) & 0xf])
    sb.write_char(digits[v & 0xf])
  }
  sb.to_string()
}

///|
test "SM4 GB/T 32907-2016 Appendix A Example 1 (single block encrypt & decrypt)" {
  let key = hex_to_bytes("0123456789abcdeffedcba9876543210")
  let plain = hex_to_bytes("0123456789abcdeffedcba9876543210")
  let expected_cipher = "681edf34d206965e86b3e94f536e4246"
  let sm4 = @sm4.Sm4Key::new(key).unwrap()
  let cipher = sm4.encrypt_block(plain).unwrap()
  assert_eq(bytes_to_hex(cipher), expected_cipher)
  let decrypted = sm4.decrypt_block(cipher).unwrap()
  assert_eq(decrypted, plain)
}

///|
test "SM4 GB/T 38635.4 Appendix A.3 SM4-ECB + PKCS#7 official test vector" {
  let k1 = hex_to_bytes("58373260f067ec48667c21c144f8bc33")
  let msg = b"Chinese IBE standard"
  assert_eq(bytes_to_hex(msg), "4368696e65736520494245207374616e64617264")
  let expected_c2 = "e05b6fac6f11b965268c994f00dba7a8bb00fd60583546cbdf4649250863f10a"
  let c2 = @sm4.encrypt_ecb_pkcs7(k1, msg).unwrap()
  assert_eq(c2.length(), 32)
  assert_eq(bytes_to_hex(c2), expected_c2)
  let recovered = @sm4.decrypt_ecb_pkcs7(k1, c2).unwrap()
  assert_eq(recovered, msg)
}

///|
test "SM4-ECB PKCS#7 boundary plaintexts (empty, 1..33 bytes, full 16B & 32B blocks)" {
  let key = hex_to_bytes("0123456789abcdeffedcba9876543210")
  let sm4 = @sm4.Sm4Key::new(key).unwrap()
  // Empty plaintext -> padded with 16 bytes of 0x10
  let ct_empty = @sm4.encrypt_ecb_pkcs7(key, b"").unwrap()
  assert_eq(ct_empty.length(), 16)
  let full_pad16 = Bytes::makei(16, fn(_) { b'\x10' })
  assert_eq(ct_empty, sm4.encrypt_block(full_pad16).unwrap())
  assert_eq(@sm4.decrypt_ecb_pkcs7(key, ct_empty), Some(b""))

  // Exact 16-byte plaintext -> extra full 16-byte 0x10 padding block (total 32 bytes)
  let block16 = hex_to_bytes("0123456789abcdeffedcba9876543210")
  let ct_16 = @sm4.encrypt_ecb_pkcs7(key, block16).unwrap()
  assert_eq(ct_16.length(), 32)
  assert_eq(bytes_to_hex(ct_16[0:16]), "681edf34d206965e86b3e94f536e4246")
  assert_eq(ct_16[16:32].to_owned(), sm4.encrypt_block(full_pad16).unwrap())
  assert_eq(@sm4.decrypt_ecb_pkcs7(key, ct_16), Some(block16))

  // Sweep lengths 0..=48 to cover every possible pad length 1..=16 across 1..=4 blocks
  for len = 0; len <= 48; len = len + 1 {
    let pt = Bytes::makei(len, fn(i) { ((i * 37 + 11) & 0xff).to_byte() })
    let ct = @sm4.encrypt_ecb_pkcs7(key, pt).unwrap()
    let expected_len = (len / 16 + 1) * 16
    assert_eq(ct.length(), expected_len)
    assert_eq(@sm4.decrypt_ecb_pkcs7(key, ct), Some(pt))
  }
}

///|
test "SM4 invalid key and block length rejection" {
  let valid_key = hex_to_bytes("0123456789abcdeffedcba9876543210")
  let valid_block = hex_to_bytes("0123456789abcdeffedcba9876543210")
  // Invalid key lengths: 0, 1, 15, 17, 32
  let bad_key_lens : Array[Int32] = [0, 1, 15, 17, 32]
  for n in bad_key_lens {
    let k = Bytes::makei(n, fn(i) { i.to_byte() })
    assert_true(@sm4.Sm4Key::new(k) is None)
    assert_true(@sm4.encrypt_ecb_pkcs7(k, b"hello") is None)
    assert_true(@sm4.decrypt_ecb_pkcs7(k, valid_block) is None)
  }
  // Invalid block lengths for encrypt_block / decrypt_block
  let sm4 = @sm4.Sm4Key::new(valid_key).unwrap()
  let bad_block_lens : Array[Int32] = [0, 1, 15, 17, 32]
  for n in bad_block_lens {
    let blk = Bytes::makei(n, fn(i) { i.to_byte() })
    assert_true(sm4.encrypt_block(blk) is None)
    assert_true(sm4.decrypt_block(blk) is None)
  }
}

///|
test "SM4-ECB PKCS#7 adversarial ciphertext & padding tampering rejection" {
  let key = hex_to_bytes("58373260f067ec48667c21c144f8bc33")
  let sm4 = @sm4.Sm4Key::new(key).unwrap()

  // Empty ciphertext and non-multiples of 16 bytes
  assert_true(@sm4.decrypt_ecb_pkcs7(key, b"") is None)
  let bad_lens : Array[Int32] = [1, 15, 17, 31, 33]
  for n in bad_lens {
    let ct = Bytes::makei(n, fn(i) { i.to_byte() })
    assert_true(@sm4.decrypt_ecb_pkcs7(key, ct) is None)
  }

  // Crafted plaintexts with invalid PKCS#7 padding values, encrypted directly as raw blocks:
  // 1. pad byte = 0x00
  let p_zero = Bytes::makei(16, fn(i) { if i < 15 { b'\x41' } else { b'\x00' } })
  let c_zero = sm4.encrypt_block(p_zero).unwrap()
  assert_true(@sm4.decrypt_ecb_pkcs7(key, c_zero) is None)

  // 2. pad byte = 0x11 (17 > 16) and 0xff (255 > 16)
  let p_17 = Bytes::makei(16, fn(_) { b'\x11' })
  assert_true(
    @sm4.decrypt_ecb_pkcs7(key, sm4.encrypt_block(p_17).unwrap()) is None,
  )
  let p_ff = Bytes::makei(16, fn(_) { b'\xff' })
  assert_true(
    @sm4.decrypt_ecb_pkcs7(key, sm4.encrypt_block(p_ff).unwrap()) is None,
  )

  // 3. Inconsistent padding bytes for every valid pad length 2..=16:
  //    corrupt each padding byte position in turn while keeping the last byte valid
  for pad = 2; pad <= 16; pad = pad + 1 {
    for corrupt_offset = 1
        corrupt_offset < pad
        corrupt_offset = corrupt_offset + 1 {
      let arr : FixedArray[Byte] = FixedArray::make(16, b'\x41')
      for j = 16 - pad; j < 16; j = j + 1 {
        arr[j] = pad.to_byte()
      }
      let target = 15 - corrupt_offset
      arr[target] = (pad ^ 1).to_byte()
      let blk = Bytes::makei(16, fn(i) { arr[i] })
      let ct = sm4.encrypt_block(blk).unwrap()
      assert_true(@sm4.decrypt_ecb_pkcs7(key, ct) is None)
    }
  }

  // 4. Bit-flip tampering on the valid GB/T 38635.4 A.3 ciphertext's last block
  let valid_c2 = @sm4.encrypt_ecb_pkcs7(key, b"Chinese IBE standard").unwrap()
  let tampered : FixedArray[Byte] = FixedArray::makei(valid_c2.length(), fn(i) {
    valid_c2[i]
  })
  tampered[31] = (tampered[31].to_int() ^ 0x01).to_byte()
  let tampered_bytes = Bytes::makei(tampered.length(), fn(i) { tampered[i] })
  assert_true(@sm4.decrypt_ecb_pkcs7(key, tampered_bytes) is None)
}

///|
/// Pure MoonBit SM9 (GB/T 38635-2020) CLI demonstration and verification tool.
/// Supports `wasm-gc`, `js`, and `native` targets with zero FFI dependencies.

///|
fn parse_hex(hex : String) -> Result[Bytes, String] {
  match @sm3.hex_to_bytes(hex) {
    Some(b) => Ok(b)
    None => Err("invalid hex literal: " + hex)
  }
}

///|
fn parse_fn_nonzero(hex : String) -> Result[@field.Fn, String] {
  match parse_hex(hex) {
    Err(e) => Err(e)
    Ok(b) =>
      match @field.Fn::from_be_bytes_nonzero(b) {
        Some(v) => Ok(v)
        None => Err("invalid non-zero Fn scalar: " + hex)
      }
  }
}

///|
fn parse_fp(hex : String) -> Result[@field.Fp, String] {
  match parse_hex(hex) {
    Err(e) => Err(e)
    Ok(b) =>
      match @field.Fp::from_be_bytes_strict(b) {
        Some(v) => Ok(v)
        None => Err("invalid Fp element: " + hex)
      }
  }
}

///|
fn concat_bytes(parts : Array[Bytes]) -> Bytes {
  let mut total = 0
  for i = 0; i < parts.length(); i = i + 1 {
    total = total + parts[i].length()
  }
  let buf = FixedArray::make(total, b'\x00')
  let mut offset = 0
  for i = 0; i < parts.length(); i = i + 1 {
    let p = parts[i]
    for j = 0; j < p.length(); j = j + 1 {
      buf[offset] = p[j]
      offset = offset + 1
    }
  }
  Bytes::from_array(buf)
}

///|
fn flip_byte(data : Bytes, idx : Int32) -> Bytes {
  Bytes::makei(data.length(), fn(i) {
    if i == idx {
      (data[i].to_int() ^ 0x01).to_byte()
    } else {
      data[i]
    }
  })
}

///|
fn hex_preview(data : Bytes, head_bytes : Int32, tail_bytes : Int32) -> String {
  let n = data.length()
  if n <= head_bytes + tail_bytes {
    @sm3.bytes_to_hex(data)
  } else {
    let head = Bytes::makei(head_bytes, fn(i) { data[i] })
    let tail = Bytes::makei(tail_bytes, fn(i) { data[n - tail_bytes + i] })
    @sm3.bytes_to_hex(head) + "..." + @sm3.bytes_to_hex(tail)
  }
}

///|
fn check_hex_eq(
  label : String,
  actual : Bytes,
  expected_hex : String,
) -> Result[Unit, String] {
  let actual_hex = @sm3.bytes_to_hex(actual)
  if actual_hex == expected_hex {
    Ok(())
  } else {
    Err(
      label +
      " mismatch:\n  actual:   " +
      actual_hex +
      "\n  expected: " +
      expected_hex,
    )
  }
}

///|
fn suite1_sm3_and_pairing() -> Result[Array[String], String] {
  let lines : Array[String] = []
  lines.push("[1/6] SM3 & BN256 Pairing")
  // Verify SM3("abc")
  let sm3_abc = @sm3.hash_hex(b"abc")
  let expected_sm3_abc = "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"
  if sm3_abc != expected_sm3_abc {
    return Err("SM3(\"abc\") mismatch: " + sm3_abc)
  }
  lines.push("      SM3(\"abc\")     : " + sm3_abc + "  [OK]")

  // Verify official 384-byte base pairing e(P2, P1)
  let p1 = @ec.G1Affine::generator()
  let p2 = @ec.G2Affine::generator()
  let e_direct = @pairing.pair_coords(p2.x(), p2.y(), p1.x(), p1.y())
  let e_kgc = @kgc.pair(p2, p1)
  if e_direct != e_kgc {
    return Err("pairing.pair_coords and kgc.pair disagree on e(P2, P1)")
  }
  let expected_e_p2_p1 = "256943fbdb2bf87ab91ae7fbeaff14e146cf7e2279b9d155d13461e09b22f523" +
    "0167b0280051495c6af1ec23ba2cd2ff1cdcdeca461a5ab0b5449e9091308310" +
    "5e7addaddf7fbfe16291b4e89af50b8217ddc47ba3cba833c6e77c3fb027685e" +
    "79d0c8337072c93fef482bb055f44d6247ccac8e8e12525854b3566236337ebe" +
    "082cde173022da8cd09b28a2d80a8cee53894436a52007f978dc37f36116d39b" +
    "3fa7ed741eaed99a58f53e3df82df7ccd3407bcc7b1d44a9441920ced5fb824f" +
    "7fc6eb2aa771d99c9234fddd31752edfd60723e05a4ebfdeb5c33fbd47e0cf06" +
    "6fa6b6fa6dd6b6d3b19a959a110e748154eef796dc0fc2dd766ea414de786968" +
    "8ffe1c0e9de45fd0fed790ac26be91f6b3f0a49c084fe29a3fb6ed288ad7994d" +
    "1664a1366beb3196f0443e15f5f9042a947354a5678430d45ba031cff06db927" +
    "7f7c6d52b475e6aaa827fdc5b4175ac6929320f782d998f86b6b57cda42a0426" +
    "36a699de7c136f78eee2dbac4ca9727bff0cee02ee920f5822e65ea170aa9669"
  let e_bytes = e_direct.to_bytes()
  match check_hex_eq("e(P2, P1)", e_bytes, expected_e_p2_p1) {
    Err(e) => return Err(e)
    Ok(_) => ()
  }
  lines.push(
    "      e(P2, P1) 384B : " + hex_preview(e_bytes, 12, 8) + "  [EXACT]",
  )

  // Verify bilinearity: e([a]P2, [b]P1) == e(P2, P1)^(a*b)
  let a = @field.Fn::from_u64(0x123456789abcdef1UL)
  let b = @field.Fn::from_u64(0xfedcba9876543213UL)
  let a_p2 = p2.scalar_mul_fn(a).to_affine()
  let b_p1 = p1.scalar_mul_fn(b).to_affine()
  let lhs = @kgc.pair(a_p2, b_p1)
  let rhs = e_direct.cyclotomic_pow_u256(a.mul(b).to_u256())
  if lhs != rhs || !@sm3.ct_eq_bytes(lhs.to_bytes(), rhs.to_bytes()) {
    return Err("Bilinearity check e([a]P2, [b]P1) == e(P2, P1)^(a*b) failed")
  }
  lines.push(
    "      Bilinearity    : e([a]P2, [b]P1) == e(P2, P1)^(a*b)  [PASS]",
  )
  Ok(lines)
}

///|
fn suite2_signature() -> Result[Array[String], String] {
  let lines : Array[String] = []
  lines.push("[2/6] GB/T 38635.2 Digital Signature")
  let ks = match
    parse_fn_nonzero(
      "000130e78459d78545cb54c587e02cf480ce0b66340f319f348a1d5b1f2dc5f4",
    ) {
    Ok(v) => v
    Err(e) => return Err(e)
  }
  let msk = match @kgc.SignMasterPrivateKey::from_fn(ks) {
    Some(k) => k
    None => return Err("SignMasterPrivateKey::from_fn rejected official ks")
  }
  let mpk = msk.public_key()
  let expected_p_pub_s = "9f64080b3084f733e48aff4b41b565011ce0711c5e392cfb0ab1b6791b94c408" +
    "29dba116152d1f786ce843ed24a3b573414d2177386a92dd8f14d65696ea5e32" +
    "69850938abea0112b57329f447e3a0cbad3e2fdb1a77f335e89e1408d0ef1c25" +
    "41e00a53dda532da1a7ce027b7a46f741006e85f5cdff0730e75c05fb4e3216d"
  match check_hex_eq("P_pub-s", mpk.to_bytes_raw(), expected_p_pub_s) {
    Err(e) => return Err(e)
    Ok(_) => ()
  }
  let id_a = b"Alice"
  let ds_a_key = match @kgc.extract_sign_private_key(msk, id_a) {
    Ok(k) => k
    Err(e) => return Err("extract_sign_private_key failed: " + e)
  }
  let expected_ds_a = "a5702f05cf1315305e2d6eb64b0deb923db1a0bcf0caff90523ac8754aa69820" +
    "78559a844411f9825c109f5ee3f52d720dd01785392a727bb1556952b2b013d3"
  match check_hex_eq("ds_A", ds_a_key.to_bytes_raw(), expected_ds_a) {
    Err(e) => return Err(e)
    Ok(_) => ()
  }
  let r = match
    parse_fn_nonzero(
      "00033c8616b06704813203dfd00965022ed15975c662337aed648835dc4b1cbe",
    ) {
    Ok(v) => v
    Err(e) => return Err(e)
  }
  let msg = b"Chinese IBS standard"
  let sig = match @sign.sign_with_r(mpk.to_g2(), ds_a_key.to_g1(), msg, r) {
    Ok(s) => s
    Err(e) => return Err("sign_with_r failed: " + e)
  }
  let expected_h = "823c4b21e4bd2dfe1ed92c606653e996668563152fc33f55d7bfbb9bd9705adb"
  let expected_s = "73bf96923ce58b6ad0e13e9643a406d8eb98417c50ef1b29cef9adb48b6d598c" +
    "856712f1c2e0968ab7769f42a99586aed139d5b8b3e15891827cc2aced9baa05"
  let h_bytes = sig.h().to_be_bytes()
  let s_bytes = sig.s().to_bytes_raw()
  match check_hex_eq("Signature.h", h_bytes, expected_h) {
    Err(e) => return Err(e)
    Ok(_) => ()
  }
  match check_hex_eq("Signature.S", s_bytes, expected_s) {
    Err(e) => return Err(e)
    Ok(_) => ()
  }
  if !@sign.verify(mpk.to_g2(), id_a, msg, sig) {
    return Err("Official SM9 signature failed verification")
  }
  lines.push("      P_pub-s / ds_A : KGC derived (128B / 64B)  [EXACT]")
  lines.push(
    "      h (32B)        : " + hex_preview(h_bytes, 12, 8) + "  [EXACT]",
  )
  lines.push(
    "      S (64B)        : " + hex_preview(s_bytes, 12, 8) + "  [EXACT]",
  )
  lines.push("      Verify(\"Alice\", \"Chinese IBS standard\")  [PASS]")
  Ok(lines)
}

///|
fn suite3_key_exchange() -> Result[Array[String], String] {
  let lines : Array[String] = []
  lines.push("[3/6] GB/T 38635.3 Key Exchange")
  let ke = match
    parse_fn_nonzero(
      "0002e65b0762d042f51f0d23542b13ed8cfa2e9a0e7206361e013a283905e31f",
    ) {
    Ok(v) => v
    Err(e) => return Err(e)
  }
  let msk = match @kgc.EncMasterPrivateKey::from_fn(ke) {
    Some(k) => k
    None => return Err("EncMasterPrivateKey::from_fn rejected Part 3 ke")
  }
  let mpk = msk.public_key()
  let expected_p_pub_e = "9174542668e8f14ab273c0945c3690c66e5dd09678b86f734c4350567ed06283" +
    "54e598c6bf749a3dacc9fffedd9db6866c50457cfc7aa2a4ad65c3168ff74210"
  match check_hex_eq("Part3 P_pub-e", mpk.to_bytes_raw(), expected_p_pub_e) {
    Err(e) => return Err(e)
    Ok(_) => ()
  }
  let id_a = b"Alice"
  let id_b = b"Bob"
  let de_a_key = match @kgc.extract_keyex_private_key(msk, id_a) {
    Ok(k) => k
    Err(e) => return Err("extract_keyex_private_key(Alice) failed: " + e)
  }
  let de_b_key = match @kgc.extract_keyex_private_key(msk, id_b) {
    Ok(k) => k
    Err(e) => return Err("extract_keyex_private_key(Bob) failed: " + e)
  }
  let expected_de_a = "0fe8eab395199b56bf1d75bd2cd610b6424f08d1092922c5882b52dcd6ca832a" +
    "7da57bc50241f9e5bfddc075dd9d32c7777100d736916cfc165d8d36e0634cd7" +
    "83a457daf52cad464c903b26062caf937bb40e37daded9eda401050e49c8ad0c" +
    "6970876b9aad1b7a50bb4863a11e574af1fe3c5975161d73de4c3af621fb1efb"
  let expected_de_b = "74ccc3ac9c383c60af083972b96d05c75f12c8907d128a17adafbab8c5a4acf7" +
    "01092ff4de89362670c21711b6dbe52dcd5f8e40c6654b3dece573c2ab3d29b2" +
    "44b0294aa04290e1524ff3e3da8cfd432bb64de3a8040b5b88d1b5fc86a4ebc1" +
    "8cfc48fb4ff37f1e27727464f3c34e2153861ad08e972d1625fc1a7bd18d5539"
  match check_hex_eq("de_A", de_a_key.to_bytes_raw(), expected_de_a) {
    Err(e) => return Err(e)
    Ok(_) => ()
  }
  match check_hex_eq("de_B", de_b_key.to_bytes_raw(), expected_de_b) {
    Err(e) => return Err(e)
    Ok(_) => ()
  }
  let r_a = match
    parse_fn_nonzero(
      "00005879dd1d51e175946f23b1b41e93ba31c584ae59a426ec1046a4d03b06c8",
    ) {
    Ok(v) => v
    Err(e) => return Err(e)
  }
  let r_b = match
    parse_fn_nonzero(
      "00018b98c44bef9f8537fb7d071b2c928b3bc65bd3d69e1eee213564905634fe",
    ) {
    Ok(v) => v
    Err(e) => return Err(e)
  }
  let p_pub_e = mpk.to_g1()
  let r_a_pt = match @keyex.generate_ephemeral(p_pub_e, id_b, r_a) {
    Ok(pt) => pt
    Err(e) => return Err("generate_ephemeral(R_A) failed: " + e)
  }
  let r_b_pt = match @keyex.generate_ephemeral(p_pub_e, id_a, r_b) {
    Ok(pt) => pt
    Err(e) => return Err("generate_ephemeral(R_B) failed: " + e)
  }
  let expected_ra = "7cba5b19069ee66aa79d490413d11846b9ba76dd22567f809cf23b6d964bb265" +
    "a9760c99cb6f706343fed05637085864958d6c90902aba7d405fbedf7b781599"
  let expected_rb = "861e91485fb7623d2794f495031a35598b493bd45be37813abc710fcc1f34482" +
    "32d906a469ebc1216a802a7052d5617cd430fb56fba729d41d9bd668e9eb9600"
  match check_hex_eq("R_A", r_a_pt.to_bytes_raw(), expected_ra) {
    Err(e) => return Err(e)
    Ok(_) => ()
  }
  match check_hex_eq("R_B", r_b_pt.to_bytes_raw(), expected_rb) {
    Err(e) => return Err(e)
    Ok(_) => ()
  }
  let res_b = match
    @keyex.responder_exchange(
      p_pub_e,
      id_a,
      id_b,
      de_b_key.to_g2(),
      r_b,
      r_a_pt,
      r_b_pt,
      16,
    ) {
    Ok(r) => r
    Err(e) => return Err("responder_exchange failed: " + e)
  }
  let res_a = match
    @keyex.initiator_exchange(
      p_pub_e,
      id_a,
      id_b,
      de_a_key.to_g2(),
      r_a,
      r_a_pt,
      r_b_pt,
      16,
      peer_s_b=res_b.s_b,
    ) {
    Ok(r) => r
    Err(e) => return Err("initiator_exchange failed: " + e)
  }
  let expected_sk = "c5c13a8f59a97cdeae64f16a2272a9e7"
  let expected_sb = "3bb4bcee8139c960b4d6566db1e0d5f0b2767680e5e1bf934103e6c66e40ffee"
  let expected_sa = "195d1b7256ba7e0e67c71202a25f8c94ff8241702c2f55d613ae1c6b98215172"
  match check_hex_eq("SK_A", res_a.sk, expected_sk) {
    Err(e) => return Err(e)
    Ok(_) => ()
  }
  match check_hex_eq("SK_B", res_b.sk, expected_sk) {
    Err(e) => return Err(e)
    Ok(_) => ()
  }
  match check_hex_eq("S_B", res_b.s_b, expected_sb) {
    Err(e) => return Err(e)
    Ok(_) => ()
  }
  match check_hex_eq("S_1", res_a.s_1, expected_sb) {
    Err(e) => return Err(e)
    Ok(_) => ()
  }
  match check_hex_eq("S_A", res_a.s_a, expected_sa) {
    Err(e) => return Err(e)
    Ok(_) => ()
  }
  match check_hex_eq("S_2", res_b.s_2, expected_sa) {
    Err(e) => return Err(e)
    Ok(_) => ()
  }
  if !@keyex.verify_responder_confirmation(res_a.s_1, res_b.s_b) ||
    !@sm3.ct_eq_bytes(res_a.s_a, res_b.s_2) {
    return Err("Key exchange mutual confirmation check failed")
  }
  lines.push(
    "      R_A / R_B (64B): " +
    hex_preview(r_a_pt.to_bytes_raw(), 6, 4) +
    " / " +
    hex_preview(r_b_pt.to_bytes_raw(), 6, 4) +
    "  [EXACT]",
  )
  lines.push(
    "      SK (16B)       : " + @sm3.bytes_to_hex(res_a.sk) + "  [EXACT]",
  )
  lines.push("      Confirm Tags   : S_B == S_1 & S_A == S_2  [PASS]")
  Ok(lines)
}

///|
fn part4_official_keys() -> Result[(@ec.G1Affine, @ec.G2Affine), String] {
  let ke = match
    parse_fn_nonzero(
      "0001edee3778f441f8dea3d9fa0acc4e07ee36c93f9a08618af4ad85cede1c22",
    ) {
    Ok(v) => v
    Err(e) => return Err(e)
  }
  let msk = match @kgc.EncMasterPrivateKey::from_fn(ke) {
    Some(k) => k
    None => return Err("EncMasterPrivateKey::from_fn rejected Part 4 ke")
  }
  let mpk = msk.public_key()
  let expected_p_pub_e = "787ed7b8a51f3ab84e0a66003f32da5c720b17eca7137d39abc66e3c80a892ff" +
    "769de61791e5adc4b9ff85a31354900b202871279a8c49dc3f220f644c57a7b1"
  match check_hex_eq("Part4 P_pub-e", mpk.to_bytes_raw(), expected_p_pub_e) {
    Err(e) => return Err(e)
    Ok(_) => ()
  }
  let de_b_key = match @kgc.extract_enc_private_key(msk, b"Bob") {
    Ok(k) => k
    Err(e) => return Err("extract_enc_private_key(Bob) failed: " + e)
  }
  let expected_de_b = "94736acd2c8c8796cc4785e938301a139a059d3537b6414140b2d31eecf41683" +
    "115bae85f5d8bc6c3dbd9e5342979acccf3c2f4f28420b1cb4f8c0b59a19b158" +
    "7aa5e47570da7600cd760a0cf7beaf71c447f3844753fe74fa7ba92ca7d3b55f" +
    "27538a62e7f7bfb51dce08704796d94c9d56734f119ea44732b50e31cdeb75c1"
  match check_hex_eq("Part4 de_B", de_b_key.to_bytes_raw(), expected_de_b) {
    Err(e) => return Err(e)
    Ok(_) => ()
  }
  Ok((mpk.to_g1(), de_b_key.to_g2()))
}

///|
fn suite4_kem() -> Result[Array[String], String] {
  let lines : Array[String] = []
  lines.push("[4/6] GB/T 38635.4 KEM (Appendix A.1)")
  let (p_pub_e, de_b) = match part4_official_keys() {
    Ok(pair) => pair
    Err(e) => return Err(e)
  }
  let r = match
    parse_fn_nonzero(
      "000074015f8489c01ef4270456f9e6475bfb602bde7f33fd482ab4e3684a6722",
    ) {
    Ok(v) => v
    Err(e) => return Err(e)
  }
  let kem = match @enc.kem_encapsulate_with_r(p_pub_e, b"Bob", 32, r) {
    Ok(o) => o
    Err(e) => return Err("kem_encapsulate_with_r failed: " + e)
  }
  let expected_c1 = "1edee2c3f465914491de44cefb2cb434ab02c308d9dc5e2067b4fed5aaac8a0f" +
    "1c9b4c435eca35ab83bb734174c0f78fde81a53374aff3b3602bbc5e37be9a4c"
  let expected_k = "4ff5cf86d2ad40c8f4bac98d76abdbde0c0e2f0a829d3f911ef5b2bce0695480"
  match check_hex_eq("KEM C1", kem.c1_bytes_raw(), expected_c1) {
    Err(e) => return Err(e)
    Ok(_) => ()
  }
  match check_hex_eq("KEM K", kem.key(), expected_k) {
    Err(e) => return Err(e)
    Ok(_) => ()
  }
  let decap = match @enc.kem_decapsulate(b"Bob", de_b, kem.c1(), 32) {
    Ok(k) => k
    Err(e) => return Err("kem_decapsulate failed: " + e)
  }
  if !@sm3.ct_eq_bytes(decap, kem.key()) {
    return Err("KEM decapsulated key does not match encapsulated key")
  }
  lines.push(
    "      C1 (64B)       : " +
    hex_preview(kem.c1_bytes_raw(), 12, 8) +
    "  [EXACT]",
  )
  lines.push(
    "      K  (32B)       : " + hex_preview(kem.key(), 12, 8) + "  [EXACT]",
  )
  lines.push("      Encap/Decap    : K_enc == K_dec (32B)  [PASS]")
  Ok(lines)
}

///|
fn suite5_encryption() -> Result[Array[String], String] {
  let lines : Array[String] = []
  lines.push("[5/6] GB/T 38635.4 Encryption (A.2 KDF-XOR & A.3 SM4-ECB-PKCS#7)")
  let (p_pub_e, de_b) = match part4_official_keys() {
    Ok(pair) => pair
    Err(e) => return Err(e)
  }
  let id_b = b"Bob"
  let msg = b"Chinese IBE standard"
  let r = match
    parse_fn_nonzero(
      "0000aac0541779c8fc45e3e2cb25c12b5d2576b2129ae8bb5ee2cbe5ec9e785c",
    ) {
    Ok(v) => v
    Err(e) => return Err(e)
  }
  // Appendix A.2: KDF-XOR
  let ct_xor = match
    @enc.encrypt_with_r(p_pub_e, id_b, msg, r, mode=@enc.KdfXor) {
    Ok(c) => c
    Err(e) => return Err("encrypt_with_r(KdfXor) failed: " + e)
  }
  let expected_ct_xor = "2445471164490618e1ee20528ff1d545b0f14c8bcaa44544f03dab5dac07d8ff" +
    "42ffca97d57cddc05ea405f2e586feb3a6930715532b8000759f13059ed59ac0" +
    "ba672387bcd6de5016a158a52bb2e7fc429197bcab70b25afee37a2b9db9f367" +
    "1b5f5b0e951489682f3e64e1378cdd5da9513b1c"
  match check_hex_eq("A.2 KDF-XOR C1||C3||C2", ct_xor, expected_ct_xor) {
    Err(e) => return Err(e)
    Ok(_) => ()
  }
  let pt_xor = match @enc.decrypt(id_b, de_b, ct_xor, mode=@enc.KdfXor) {
    Ok(p) => p
    Err(e) => return Err("decrypt(KdfXor) failed: " + e)
  }
  if pt_xor != msg {
    return Err("KDF-XOR decrypted plaintext mismatch")
  }
  lines.push(
    "      A.2 KDF-XOR    : 116B C1||C3||C2 " +
    hex_preview(ct_xor, 8, 8) +
    "  [EXACT]",
  )

  // Appendix A.3: SM4-ECB-PKCS#7
  let ct_sm4 = match
    @enc.encrypt_with_r(p_pub_e, id_b, msg, r, mode=@enc.Sm4EcbPkcs7) {
    Ok(c) => c
    Err(e) => return Err("encrypt_with_r(Sm4EcbPkcs7) failed: " + e)
  }
  let expected_ct_sm4 = "2445471164490618e1ee20528ff1d545b0f14c8bcaa44544f03dab5dac07d8ff" +
    "42ffca97d57cddc05ea405f2e586feb3a6930715532b8000759f13059ed59ac0" +
    "fd3c98dd92c44c68332675a370cceede31e0c5cd209c257601149d12b394a2be" +
    "e05b6fac6f11b965268c994f00dba7a8bb00fd60583546cbdf4649250863f10a"
  match check_hex_eq("A.3 SM4-ECB C1||C3||C2", ct_sm4, expected_ct_sm4) {
    Err(e) => return Err(e)
    Ok(_) => ()
  }
  let pt_sm4 = match @enc.decrypt(id_b, de_b, ct_sm4, mode=@enc.Sm4EcbPkcs7) {
    Ok(p) => p
    Err(e) => return Err("decrypt(Sm4EcbPkcs7) failed: " + e)
  }
  if pt_sm4 != msg {
    return Err("SM4-ECB-PKCS#7 decrypted plaintext mismatch")
  }
  lines.push(
    "      A.3 SM4-ECB    : 128B C1||C3||C2 " +
    hex_preview(ct_sm4, 8, 8) +
    "  [EXACT]",
  )
  lines.push(
    "      Decrypted      : \"" + @utf8.decode_lossy(pt_sm4) + "\"  [PASS]",
  )
  Ok(lines)
}

///|
fn suite6_adversarial() -> Result[Array[String], String] {
  let lines : Array[String] = []
  lines.push("[6/6] Adversarial Security Checks")

  // 1. Off-curve G1 point rejected
  let off_g1_checked = @ec.G1Affine::from_coords_checked(
    @field.Fp::from_u64(1UL),
    @field.Fp::from_u64(1UL),
  )
  let p1_corrupted = flip_byte(@ec.G1Affine::generator().to_bytes_raw(), 63)
  let off_g1_decoded = @ec.G1Affine::from_bytes_raw_strict(p1_corrupted)
  if !(off_g1_checked is None) || !(off_g1_decoded is None) {
    return Err("Adversarial check failed: off-curve G1 point was not rejected")
  }
  lines.push("      Off-curve G1   : rejected by strict decoder  [BLOCKED]")

  // 2. Non-G2 cofactor point (lies on y^2 = x^3 + 5u, outside prime-order subgroup)
  let cf_x0 = match
    parse_fp("0000000000000000000000000000000000000000000000000000000000000001") {
    Ok(v) => v
    Err(e) => return Err(e)
  }
  let cf_x1 = cf_x0
  let cf_y1 = match
    parse_fp("9324098b67dd1ccfb2bc8054215aaf13516d207bd61c4b8b3876c76edf7aa9ec") {
    Ok(v) => v
    Err(e) => return Err(e)
  }
  let cf_y0 = match
    parse_fp("9782d17c0113ff75963b71b2afb4eb089a6c6ac94e599b48be78baaf3a5d5f96") {
    Ok(v) => v
    Err(e) => return Err(e)
  }
  let cf_x = @field.Fp2::new(cf_x0, cf_x1)
  let cf_y = @field.Fp2::new(cf_y0, cf_y1)
  if cf_y.sqr() != cf_x.sqr().mul(cf_x).add(@field.Fp2::b_twist()) {
    return Err("Internal error: cofactor test point is not on E'(Fp2)")
  }
  let cf_raw = match
    parse_hex(
      "0000000000000000000000000000000000000000000000000000000000000001" +
      "0000000000000000000000000000000000000000000000000000000000000001" +
      "9324098b67dd1ccfb2bc8054215aaf13516d207bd61c4b8b3876c76edf7aa9ec" +
      "9782d17c0113ff75963b71b2afb4eb089a6c6ac94e599b48be78baaf3a5d5f96",
    ) {
    Ok(b) => b
    Err(e) => return Err(e)
  }
  if !(@ec.G2Affine::from_coords_checked(cf_x, cf_y) is None) ||
    !(@ec.G2Affine::from_bytes_raw_strict(cf_raw) is None) {
    return Err(
      "Adversarial check failed: non-subgroup G2 cofactor point was not rejected",
    )
  }
  lines.push(
    "      G2 Cofactor Pt : on E'(Fp2), outside G2 subgroup  [BLOCKED]",
  )

  // 3. Forged / tampered signature rejected
  let ks = @kgc.SignMasterPrivateKey::from_seed(b"adversarial-sign-seed")
  let p_pub_s = ks.public_key().to_g2()
  let ds_a = match @kgc.extract_sign_private_key(ks, b"Alice") {
    Ok(k) => k.to_g1()
    Err(e) => return Err(e)
  }
  let valid_sig = match
    @sign.sign_deterministic(p_pub_s, ds_a, b"authentic", b"nonce-1") {
    Ok(s) => s
    Err(e) => return Err(e)
  }
  let forged_h = valid_sig.h().add(@field.Fn::one())
  let forged_sig = match @sign.Signature::new_checked(forged_h, valid_sig.s()) {
    Some(s) => s
    None => return Err("failed to build forged signature fixture")
  }
  if @sign.verify(p_pub_s, b"Alice", b"tampered", valid_sig) ||
    @sign.verify(p_pub_s, b"Alice", b"authentic", forged_sig) {
    return Err("Adversarial check failed: forged signature was accepted")
  }
  lines.push(
    "      Forged Sig     : tampered msg & mutated h rejected  [BLOCKED]",
  )

  // 4. Tampered ciphertext MAC (C3) and body (C2) rejected
  let ke = @kgc.EncMasterPrivateKey::from_seed(b"adversarial-enc-seed")
  let p_pub_e = ke.public_key().to_g1()
  let de_b = match @kgc.extract_enc_private_key(ke, b"Bob") {
    Ok(k) => k.to_g2()
    Err(e) => return Err(e)
  }
  let ct_xor = match
    @enc.encrypt_deterministic(
      p_pub_e,
      b"Bob",
      b"secret payload",
      b"enc-nonce-xor",
      mode=@enc.KdfXor,
    ) {
    Ok(c) => c
    Err(e) => return Err(e)
  }
  let ct_sm4 = match
    @enc.encrypt_deterministic(
      p_pub_e,
      b"Bob",
      b"secret payload",
      b"enc-nonce-sm4",
      mode=@enc.Sm4EcbPkcs7,
    ) {
    Ok(c) => c
    Err(e) => return Err(e)
  }
  let bad_mac_xor = flip_byte(ct_xor, 64)
  let bad_body_xor = flip_byte(ct_xor, ct_xor.length() - 1)
  let bad_mac_sm4 = flip_byte(ct_sm4, 64)
  let bad_body_sm4 = flip_byte(ct_sm4, ct_sm4.length() - 1)
  match @enc.decrypt(b"Bob", de_b, bad_mac_xor, mode=@enc.KdfXor) {
    Ok(_) =>
      return Err("Adversarial check failed: KDF-XOR tampered MAC accepted")
    Err(_) => ()
  }
  match @enc.decrypt(b"Bob", de_b, bad_body_xor, mode=@enc.KdfXor) {
    Ok(_) =>
      return Err("Adversarial check failed: KDF-XOR tampered body accepted")
    Err(_) => ()
  }
  match @enc.decrypt(b"Bob", de_b, bad_mac_sm4, mode=@enc.Sm4EcbPkcs7) {
    Ok(_) => return Err("Adversarial check failed: SM4 tampered MAC accepted")
    Err(_) => ()
  }
  match @enc.decrypt(b"Bob", de_b, bad_body_sm4, mode=@enc.Sm4EcbPkcs7) {
    Ok(_) => return Err("Adversarial check failed: SM4 tampered body accepted")
    Err(_) => ()
  }
  lines.push(
    "      Tampered MAC   : C3 & C2 bit-flips rejected (XOR/SM4)  [BLOCKED]",
  )
  Ok(lines)
}

///|
fn append_lines(dst : Array[String], src : Array[String]) -> Unit {
  for i = 0; i < src.length(); i = i + 1 {
    dst.push(src[i])
  }
}

///|
fn run_selftest() -> Result[Array[String], String] {
  let out : Array[String] = []
  out.push(
    "======================================================================",
  )
  out.push(
    "  moonsm9 — Pure MoonBit SM9 Cryptography Suite (GB/T 38635-2020)",
  )
  out.push("  Zero-FFI | Constant-Time BN256 | Wasm-GC / JS / Native Verified")
  out.push(
    "======================================================================",
  )

  let suites : Array[Result[Array[String], String]] = [
    suite1_sm3_and_pairing(),
    suite2_signature(),
    suite3_key_exchange(),
    suite4_kem(),
    suite5_encryption(),
    suite6_adversarial(),
  ]
  for i = 0; i < suites.length(); i = i + 1 {
    match suites[i] {
      Ok(lines) => {
        append_lines(out, lines)
        out.push(
          "----------------------------------------------------------------------",
        )
      }
      Err(e) => return Err(e)
    }
  }
  out.push("[PASS] All 6 GB/T 38635-2020 verification suites passed!")
  out.push(
    "======================================================================",
  )
  Ok(out)
}

///|
fn run_sm3_cmd(text : String) -> Result[Array[String], String] {
  let data = @utf8.encode(text)
  let digest = @sm3.hash_hex(data)
  Ok([
    "SM3 Input  : " + text,
    "SM3 Bytes  : " + data.length().to_string(),
    "SM3 Digest : " + digest,
  ])
}

///|
fn run_keygen_cmd(seed : String, id : String) -> Result[Array[String], String] {
  let seed_bytes = @utf8.encode(seed)
  let id_bytes = @utf8.encode(id)
  let sign_msk = @kgc.SignMasterPrivateKey::from_seed(seed_bytes)
  let sign_mpk = sign_msk.public_key()
  let ds_user = match @kgc.extract_sign_private_key(sign_msk, id_bytes) {
    Ok(k) => k
    Err(e) => return Err("extract_sign_private_key failed: " + e)
  }
  let enc_msk = @kgc.EncMasterPrivateKey::from_seed(seed_bytes)
  let enc_mpk = enc_msk.public_key()
  let de_enc = match @kgc.extract_enc_private_key(enc_msk, id_bytes) {
    Ok(k) => k
    Err(e) => return Err("extract_enc_private_key failed: " + e)
  }
  let de_keyex = match @kgc.extract_keyex_private_key(enc_msk, id_bytes) {
    Ok(k) => k
    Err(e) => return Err("extract_keyex_private_key failed: " + e)
  }
  Ok([
    "=== SM9 Deterministic KGC Key Generation ===",
    "Seed    : " + seed,
    "User ID : " + id,
    "[Signing KGC (hid=0x01)]",
    "  ks (32B)        : " + @sm3.bytes_to_hex(sign_msk.to_bytes()),
    "  P_pub-s (128B)  : " + hex_preview(sign_mpk.to_bytes_raw(), 16, 12),
    "  ds_user (64B)   : " + hex_preview(ds_user.to_bytes_raw(), 16, 12),
    "[Encryption & KeyEx KGC (hid=0x03 / 0x02)]",
    "  ke (32B)        : " + @sm3.bytes_to_hex(enc_msk.to_bytes()),
    "  P_pub-e (64B)   : " + hex_preview(enc_mpk.to_bytes_raw(), 16, 12),
    "  de_enc (128B)   : " + hex_preview(de_enc.to_bytes_raw(), 16, 12),
    "  de_keyex (128B) : " + hex_preview(de_keyex.to_bytes_raw(), 16, 12),
  ])
}

///|
fn run_sign_cmd(
  seed : String,
  id : String,
  message : String,
) -> Result[Array[String], String] {
  let seed_bytes = @utf8.encode(seed)
  let id_bytes = @utf8.encode(id)
  let msg_bytes = @utf8.encode(message)
  let msk = @kgc.SignMasterPrivateKey::from_seed(seed_bytes)
  let mpk = msk.public_key()
  let ds_user = match @kgc.extract_sign_private_key(msk, id_bytes) {
    Ok(k) => k
    Err(e) => return Err("extract_sign_private_key failed: " + e)
  }
  let entropy = @sm3.hash(
    concat_bytes([b"moonsm9:cli:sign:", seed_bytes, b":", id_bytes]),
  )
  let sig = match
    @sign.sign_deterministic(mpk.to_g2(), ds_user.to_g1(), msg_bytes, entropy) {
    Ok(s) => s
    Err(e) => return Err("sign_deterministic failed: " + e)
  }
  let verified = @sign.verify(mpk.to_g2(), id_bytes, msg_bytes, sig)
  if !verified {
    return Err("signature verification unexpectedly failed")
  }
  Ok([
    "=== SM9 Digital Signature (GB/T 38635.2) ===",
    "Signer ID : " + id,
    "Message   : " + message,
    "h (32B)   : " + @sm3.bytes_to_hex(sig.h().to_be_bytes()),
    "S (64B)   : " + @sm3.bytes_to_hex(sig.s().to_bytes_raw()),
    "Verify    : PASS",
  ])
}

///|
fn run_keyex_cmd(
  seed : String,
  id_a : String,
  id_b : String,
) -> Result[Array[String], String] {
  let seed_bytes = @utf8.encode(seed)
  let id_a_bytes = @utf8.encode(id_a)
  let id_b_bytes = @utf8.encode(id_b)
  let msk = @kgc.EncMasterPrivateKey::from_seed(seed_bytes)
  let mpk = msk.public_key()
  let p_pub_e = mpk.to_g1()
  let de_a = match @kgc.extract_keyex_private_key(msk, id_a_bytes) {
    Ok(k) => k.to_g2()
    Err(e) => return Err("extract_keyex_private_key(A) failed: " + e)
  }
  let de_b = match @kgc.extract_keyex_private_key(msk, id_b_bytes) {
    Ok(k) => k.to_g2()
    Err(e) => return Err("extract_keyex_private_key(B) failed: " + e)
  }
  // Deterministically derive non-zero ephemeral scalars r_A, r_B in [1, N-1]
  let r_a = @kgc.h1_scalar(
    concat_bytes([b"moonsm9:cli:keyex:A:", seed_bytes, id_a_bytes, id_b_bytes]),
    @kgc.HID_KEYEX,
  )
  let r_b = @kgc.h1_scalar(
    concat_bytes([b"moonsm9:cli:keyex:B:", seed_bytes, id_a_bytes, id_b_bytes]),
    @kgc.HID_KEYEX,
  )
  let r_a_pt = match @keyex.generate_ephemeral(p_pub_e, id_b_bytes, r_a) {
    Ok(pt) => pt
    Err(e) => return Err("generate_ephemeral(A) failed: " + e)
  }
  let r_b_pt = match @keyex.generate_ephemeral(p_pub_e, id_a_bytes, r_b) {
    Ok(pt) => pt
    Err(e) => return Err("generate_ephemeral(B) failed: " + e)
  }
  let res_b = match
    @keyex.responder_exchange(
      p_pub_e, id_a_bytes, id_b_bytes, de_b, r_b, r_a_pt, r_b_pt, 32,
    ) {
    Ok(r) => r
    Err(e) => return Err("responder_exchange failed: " + e)
  }
  let res_a = match
    @keyex.initiator_exchange(
      p_pub_e,
      id_a_bytes,
      id_b_bytes,
      de_a,
      r_a,
      r_a_pt,
      r_b_pt,
      32,
      peer_s_b=res_b.s_b,
    ) {
    Ok(r) => r
    Err(e) => return Err("initiator_exchange failed: " + e)
  }
  if !@sm3.ct_eq_bytes(res_a.sk, res_b.sk) ||
    !@keyex.verify_responder_confirmation(res_a.s_1, res_b.s_b) ||
    !@sm3.ct_eq_bytes(res_a.s_a, res_b.s_2) {
    return Err("key exchange confirmation or shared key mismatch")
  }
  Ok([
    "=== SM9 Key Exchange Protocol (GB/T 38635.3) ===",
    "Initiator (A) : " + id_a,
    "Responder (B) : " + id_b,
    "R_A (64B)     : " + hex_preview(r_a_pt.to_bytes_raw(), 12, 8),
    "R_B (64B)     : " + hex_preview(r_b_pt.to_bytes_raw(), 12, 8),
    "SK (32B)      : " + @sm3.bytes_to_hex(res_a.sk),
    "S_B == S_1    : " + @sm3.bytes_to_hex(res_b.s_b) + "  [CONFIRMED]",
    "S_A == S_2    : " + @sm3.bytes_to_hex(res_a.s_a) + "  [CONFIRMED]",
  ])
}

///|
fn run_encrypt_cmd(
  seed : String,
  id : String,
  message : String,
  mode_name : String,
) -> Result[Array[String], String] {
  let (mode, mode_label) = match mode_name {
    "xor" | "kdf-xor" => (@enc.KdfXor, "KDF-XOR (Appendix A.2)")
    "sm4" | "sm4-ecb" => (@enc.Sm4EcbPkcs7, "SM4-ECB-PKCS#7 (Appendix A.3)")
    _ =>
      return Err(
        "Unknown encryption mode '" + mode_name + "'. Expected 'xor' or 'sm4'.",
      )
  }
  let seed_bytes = @utf8.encode(seed)
  let id_bytes = @utf8.encode(id)
  let msg_bytes = @utf8.encode(message)
  let msk = @kgc.EncMasterPrivateKey::from_seed(seed_bytes)
  let mpk = msk.public_key()
  let de_user = match @kgc.extract_enc_private_key(msk, id_bytes) {
    Ok(k) => k.to_g2()
    Err(e) => return Err("extract_enc_private_key failed: " + e)
  }
  let entropy = @sm3.hash(
    concat_bytes([b"moonsm9:cli:enc:", seed_bytes, b":", id_bytes]),
  )
  let ct = match
    @enc.encrypt_deterministic(mpk.to_g1(), id_bytes, msg_bytes, entropy, mode~) {
    Ok(c) => c
    Err(e) => return Err("encrypt_deterministic failed: " + e)
  }
  let pt = match @enc.decrypt(id_bytes, de_user, ct, mode~) {
    Ok(p) => p
    Err(e) => return Err("decrypt failed: " + e)
  }
  if pt != msg_bytes {
    return Err("decrypted plaintext does not match input message")
  }
  Ok([
    "=== SM9 Public-Key Encryption (GB/T 38635.4) ===",
    "Recipient ID : " + id,
    "Mode         : " + mode_label,
    "Ciphertext   : " + @sm3.bytes_to_hex(ct),
    "CT Length    : " + ct.length().to_string() + " bytes (C1 || C3 || C2)",
    "Decrypted    : " + @utf8.decode_lossy(pt),
    "Round-Trip   : PASS",
  ])
}

///|
fn usage_lines() -> Array[String] {
  [
    "moonsm9 — Pure MoonBit SM9 Cryptography CLI (GB/T 38635-2020)", "", "Usage:",
    "  moon run cmd/main [-- <command> [args...]]", "", "Commands:", "  selftest                             Run all 6 official GB/T 38635-2020 verification suites (default)",
    "  sm3 <text>                           Compute SM3 hex digest of <text>", "  keygen <seed> <id>                   Derive deterministic master keys and user private keys for <id>",
    "  sign <seed> <id> <message>           Run KGC -> deterministic SM9 sign -> verify",
    "  keyex <seed> <id_a> <id_b>           Run SM9 key exchange handshake with mutual confirmation",
    "  encrypt <seed> <id> <msg> [xor|sm4]  Run SM9 encrypt & decrypt round-trip (default mode: xor)",
    "  help | --help | -h                   Display this help message",
  ]
}

///|
fn is_known_subcommand(arg : String) -> Bool {
  match arg {
    "selftest"
    | "sm3"
    | "keygen"
    | "sign"
    | "keyex"
    | "encrypt"
    | "help"
    | "--help"
    | "-h" => true
    _ => false
  }
}

///|
fn extract_subcommand_args(raw_args : Array[String]) -> Array[String] {
  let n = raw_args.length()
  if n == 0 {
    return []
  }
  // If argv[0] is already a known subcommand (some runtimes omit program name), keep as-is.
  if is_known_subcommand(raw_args[0]) {
    return raw_args
  }
  // Otherwise drop argv[0] (executable/script path).
  let out : Array[String] = []
  for i = 1; i < n; i = i + 1 {
    out.push(raw_args[i])
  }
  out
}

///|
fn execute_cli(args : Array[String]) -> Result[Array[String], String] {
  if args.length() == 0 {
    return run_selftest()
  }
  match args[0] {
    "selftest" => run_selftest()
    "help" | "--help" | "-h" => Ok(usage_lines())
    "sm3" =>
      if args.length() < 2 {
        Err("Usage: sm3 <text>")
      } else {
        run_sm3_cmd(args[1])
      }
    "keygen" =>
      if args.length() < 3 {
        Err("Usage: keygen <seed> <id>")
      } else {
        run_keygen_cmd(args[1], args[2])
      }
    "sign" =>
      if args.length() < 4 {
        Err("Usage: sign <seed> <id> <message>")
      } else {
        run_sign_cmd(args[1], args[2], args[3])
      }
    "keyex" =>
      if args.length() < 4 {
        Err("Usage: keyex <seed> <id_a> <id_b>")
      } else {
        run_keyex_cmd(args[1], args[2], args[3])
      }
    "encrypt" =>
      if args.length() < 4 {
        Err("Usage: encrypt <seed> <id> <message> [xor|sm4]")
      } else {
        let mode_name = if args.length() >= 5 { args[4] } else { "xor" }
        run_encrypt_cmd(args[1], args[2], args[3], mode_name)
      }
    other =>
      Err("Unknown command '" + other + "'. Run with 'help' to see usage.")
  }
}

///|
fn main {
  let cmd_args = extract_subcommand_args(@env.args())
  match execute_cli(cmd_args) {
    Ok(lines) =>
      for i = 0; i < lines.length(); i = i + 1 {
        println(lines[i])
      }
    Err(msg) => {
      println("[FAIL] " + msg)
      abort(msg)
    }
  }
}

///|
fn bench_scalar_from_hex(hex : String) -> @field.Fn {
  let bytes = match @moonsm9.hex_to_bytes(hex) {
    Some(b) => b
    None => abort("invalid bench hex")
  }
  match @field.Fn::from_be_bytes_nonzero(bytes) {
    Some(v) => v
    None => abort("invalid bench scalar")
  }
}

///|
test "sm3_64b" (b : @bench.T) {
  let msg = Bytes::makei(64, fn(i) { (i & 0xff).to_byte() })
  b.bench(fn() { b.keep(@moonsm9.sm3_hash(msg)) })
}

///|
test "sm3_1kb" (b : @bench.T) {
  let msg = Bytes::makei(1024, fn(i) { (i & 0xff).to_byte() })
  b.bench(fn() { b.keep(@moonsm9.sm3_hash(msg)) })
}

///|
test "fp12_mul" (b : @bench.T) {
  let p1 = @ec.G1Affine::generator()
  let p2 = @ec.G2Affine::generator()
  let a = @moonsm9.pair(p2, p1)
  let c = a.cyclotomic_sqr()
  b.bench(fn() { b.keep(a.mul(c)) })
}

///|
test "fp12_cyclotomic_sqr" (b : @bench.T) {
  let p1 = @ec.G1Affine::generator()
  let p2 = @ec.G2Affine::generator()
  let a = @moonsm9.pair(p2, p1)
  b.bench(fn() { b.keep(a.cyclotomic_sqr()) })
}

///|
test "g1_scalar_mul" (b : @bench.T) {
  let p1 = @ec.G1Affine::generator()
  let k = bench_scalar_from_hex(
    "291fe3cac8f58ad2dc462c8d4d578a94dafd5624ddc28e328d2936688a86cf1a",
  )
  b.bench(fn() { b.keep(p1.scalar_mul_fn(k)) })
}

///|
test "g2_scalar_mul" (b : @bench.T) {
  let p2 = @ec.G2Affine::generator()
  let k = bench_scalar_from_hex(
    "291fe3cac8f58ad2dc462c8d4d578a94dafd5624ddc28e328d2936688a86cf1a",
  )
  b.bench(fn() { b.keep(p2.scalar_mul_fn(k)) })
}

///|
test "rate_pairing" (b : @bench.T) {
  let p1 = @ec.G1Affine::generator()
  let p2 = @ec.G2Affine::generator()
  b.bench(fn() { b.keep(@moonsm9.pair(p2, p1)) })
}

///|
test "sm9_sign" (b : @bench.T) {
  let master = @moonsm9.sign_master_from_seed(b"bench-sign-master")
  let p_pub_s = master.public_key()
  let ds_a = match @moonsm9.extract_sign_key(master, b"Alice") {
    Ok(k) => k
    Err(e) => abort(e)
  }
  let msg = b"Chinese IBS standard"
  let r = bench_scalar_from_hex(
    "00033c8616b06704813203dfd00965022ed15975c662337aed648835dc4b1cbe",
  )
  b.bench(fn() { b.keep(@moonsm9.sign_with_r(p_pub_s, ds_a, msg, r)) })
}

///|
test "sm9_verify" (b : @bench.T) {
  let master = @moonsm9.sign_master_from_seed(b"bench-sign-master")
  let p_pub_s = master.public_key()
  let ds_a = match @moonsm9.extract_sign_key(master, b"Alice") {
    Ok(k) => k
    Err(e) => abort(e)
  }
  let msg = b"Chinese IBS standard"
  let sig = match @moonsm9.sign(p_pub_s, ds_a, msg) {
    Ok(s) => s
    Err(e) => abort(e)
  }
  b.bench(fn() { b.keep(@moonsm9.verify(p_pub_s, b"Alice", msg, sig)) })
}

///|
test "sm9_keyex_roundtrip" (b : @bench.T) {
  let master = @moonsm9.enc_master_from_seed(b"bench-keyex-master")
  let p_pub_e = master.public_key()
  let de_a = match @moonsm9.extract_keyex_key(master, b"Alice") {
    Ok(k) => k
    Err(e) => abort(e)
  }
  let de_b = match @moonsm9.extract_keyex_key(master, b"Bob") {
    Ok(k) => k
    Err(e) => abort(e)
  }
  let r_a = bench_scalar_from_hex(
    "00005879dd1d51e175946f23b1b41e93ba31c584ae59a426ec1046a4d03b06c8",
  )
  let r_b = bench_scalar_from_hex(
    "00018b98c44bef9f8537fb7d071b2c928b3bc65bd3d69e1eee213564905634fe",
  )
  let ra_pt = match @moonsm9.keyex_ephemeral(p_pub_e, b"Bob", r_a) {
    Ok(pt) => pt
    Err(e) => abort(e)
  }
  let rb_pt = match @moonsm9.keyex_ephemeral(p_pub_e, b"Alice", r_b) {
    Ok(pt) => pt
    Err(e) => abort(e)
  }
  b.bench(fn() {
    let resp = match
      @moonsm9.keyex_responder(
        p_pub_e, b"Alice", b"Bob", de_b, r_b, ra_pt, rb_pt, 16,
      ) {
      Ok(v) => v
      Err(e) => abort(e)
    }
    let init = match
      @moonsm9.keyex_initiator(
        p_pub_e,
        b"Alice",
        b"Bob",
        de_a,
        r_a,
        ra_pt,
        rb_pt,
        16,
        peer_s_b=resp.s_b,
      ) {
      Ok(v) => v
      Err(e) => abort(e)
    }
    b.keep(init)
  })
}

///|
test "sm9_kem_encap_decap" (b : @bench.T) {
  let master = @moonsm9.enc_master_from_seed(b"bench-kem-master")
  let p_pub_e = master.public_key()
  let de_b = match @moonsm9.extract_enc_key(master, b"Bob") {
    Ok(k) => k
    Err(e) => abort(e)
  }
  let r = bench_scalar_from_hex(
    "000074015f8489c01ef4270456f9e6475bfb602bde7f33fd482ab4e3684a6722",
  )
  b.bench(fn() {
    let encap = match @moonsm9.kem_encapsulate_with_r(p_pub_e, b"Bob", 32, r) {
      Ok(v) => v
      Err(e) => abort(e)
    }
    let decap = match @moonsm9.kem_decapsulate(b"Bob", de_b, encap.c1(), 32) {
      Ok(k) => k
      Err(e) => abort(e)
    }
    b.keep(decap)
  })
}

///|
test "sm9_encrypt_decrypt_xor" (b : @bench.T) {
  let master = @moonsm9.enc_master_from_seed(b"bench-enc-master")
  let p_pub_e = master.public_key()
  let de_b = match @moonsm9.extract_enc_key(master, b"Bob") {
    Ok(k) => k
    Err(e) => abort(e)
  }
  let msg = b"Chinese IBE standard"
  let r = bench_scalar_from_hex(
    "0000aac0541779c8fc45e3e2cb25c12b5d2576b2129ae8bb5ee2cbe5ec9e785c",
  )
  b.bench(fn() {
    let ct = match
      @moonsm9.encrypt_with_r(
        p_pub_e,
        b"Bob",
        msg,
        r,
        mode=@enc.EncMode::KdfXor,
      ) {
      Ok(c) => c
      Err(e) => abort(e)
    }
    let pt = match
      @moonsm9.decrypt(b"Bob", de_b, ct, mode=@enc.EncMode::KdfXor) {
      Ok(p) => p
      Err(e) => abort(e)
    }
    b.keep(pt)
  })
}

///|
test "sm9_encrypt_decrypt_sm4" (b : @bench.T) {
  let master = @moonsm9.enc_master_from_seed(b"bench-enc-master")
  let p_pub_e = master.public_key()
  let de_b = match @moonsm9.extract_enc_key(master, b"Bob") {
    Ok(k) => k
    Err(e) => abort(e)
  }
  let msg = b"Chinese IBE standard"
  let r = bench_scalar_from_hex(
    "0000aac0541779c8fc45e3e2cb25c12b5d2576b2129ae8bb5ee2cbe5ec9e785c",
  )
  b.bench(fn() {
    let ct = match
      @moonsm9.encrypt_with_r(
        p_pub_e,
        b"Bob",
        msg,
        r,
        mode=@enc.EncMode::Sm4EcbPkcs7,
      ) {
      Ok(c) => c
      Err(e) => abort(e)
    }
    let pt = match
      @moonsm9.decrypt(b"Bob", de_b, ct, mode=@enc.EncMode::Sm4EcbPkcs7) {
      Ok(p) => p
      Err(e) => abort(e)
    }
    b.keep(pt)
  })
}

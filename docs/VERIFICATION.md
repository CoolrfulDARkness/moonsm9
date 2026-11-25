# moonsm9 Verification, Test Vectors & Benchmarks

This document records the independent mathematical verification methodology, GB/T 38635-2020 official test vector coverage, algebraic identity checks, adversarial security tests, and multi-target (`wasm`, `wasm-gc`, `js`, `native`) qualification status of `CoolrfulDARkness/moonsm9`.

---

## 1. Independent Python 3 Reference Cross-Verification

Before implementing any MoonBit protocol package, all curve parameters, Montgomery precomputed limbs, 13 Frobenius constants, tower basis permutations, and GB/T 38635.1–.5 Appendix A test vectors were independently derived and verified in pure Python 3 from first principles, cross-checked against GB/T 38635-2020 (equivalent to GM/T 0044-2016) and authoritative open-source references (`guanzhi/GmSSL` and `emmansun/gmsm`):

1. **Dual-Tower Equivalence Verification**: Computed BN256 R-ate pairings independently under both Standard Tower A ($\mathbb{F}_{p^2} \to \mathbb{F}_{p^4} \to \mathbb{F}_{p^{12}}$ with direct textbook exponentiation $f^{(p^{12}-1)/N}$) and Optimized Tower B ($\mathbb{F}_{p^2} \to \mathbb{F}_{p^6} \to \mathbb{F}_{p^{12}}$ with Fuentes-Castaneda cyclotomic final exponentiation and zero-cost permutation `[c1.c2, c0.c1, c0.c2, c1.c0, c1.c1, c0.c0]`), confirming 100% bit-for-bit equality across all 384 bytes.
2. **Twist Disambiguation**: Verified explicitly that generator $P_2$ satisfies the D-type twist equation $y^2 = x^3 + 5u$ (`True`) and fails $y^2 = x^3 + 5/u$ (`False`), and satisfies $[N]P_2 = \mathcal{O}$.
3. **End-to-End Official Vector Match**: Confirmed 100% bit-exact agreement on every intermediate value (`H1`, `t1`, `t2`, `P_pub-s`, `ds_A`, `P_pub-e`, `de_A`, `de_B`, `Q_A`, `Q_B`, `g`, `w`, `g1`, `g2`, `g3`) and final output (`h`, `S`, `R_A`, `R_B`, `SK`, `S_B`, `S_1`, `S_A`, `S_2`, `C1`, `K`, `K1`, `K2`, `C2`, `C3`, `C1||C3||C2`) across Parts 2, 3, and 4 (A.1 / A.2 / A.3).

---

## 2. Official Test Vector Coverage Matrix

Every official test vector below is asserted byte-for-byte in the MoonBit test suite across all compilation targets:

| Standard & Vector | Package(s) | Key Inputs | Verified Output Fingerprint (Hex) |
|---|---|---|---|
| **GB/T 32905-2016** SM3 App. A.1 | `sm3` | `"abc"` | `66c7f0f462eeedd9...297da02b8f4ba8e0` (32B) |
| **GB/T 32905-2016** SM3 App. A.2 | `sm3` | `"abcd"` × 16 (64B) | `debe9ff92275b8a1...293dcba39c0c5732` (32B) |
| **GB/T 32905-2016** SM3 Empty | `sm3` | `""` (0B) | `1ab21d8355cfa17f...7ed035eb5082aa2b` (32B) |
| **GB/T 32907-2016** SM4 App. A.1 | `sm4` | `key = plain = 0123456789abcdeffedcba9876543210` | `cipher = 681edf34d206965e86b3e94f536e4246` (16B) |
| **GB/T 38635.5** Base Pairing $e(P_2, P_1)$ | `field`, `pairing` | Generators $P_2 \in \mathbb{G}_2, P_1 \in \mathbb{G}_1$ | `256943fbdb2bf87a...22e65ea170aa9669` (384B) |
| **GB/T 38635.2** Part 2 App. A (KGC & Signature) | `ec`, `pairing`, `kgc`, `sign`, root, `cmd/main` | `ID_A = "Alice"`, `hid = 0x01`, `M = "Chinese IBS standard"`, `ks = 000130e7...1f2dc5f4`, `r = 00033c86...dc4b1cbe` | `H1 = 2acc468c...67862fab`<br/>`ds_A.x = a5702f05...4aa69820`<br/>`h = 823c4b21e4bd2dfe...d7bfbb9bd9705adb`<br/>`S.x = 73bf96923ce58b6a...cef9adb48b6d598c`<br/>`S.y = 856712f1c2e0968a...827cc2aced9baa05` |
| **GB/T 38635.3** Part 3 App. A (Key Exchange) | `ec`, `pairing`, `kgc`, `keyex`, root, `cmd/main` | `ID_A = "Alice"`, `ID_B = "Bob"`, `hid = 0x02`, `klen = 16`, `ke = 0002e65b...3905e31f`, `r_A`, `r_B` | `R_A.x = 7cba5b19...964bb265`<br/>`R_B.x = 861e9148...c1f34482`<br/>`SK_A == SK_B = c5c13a8f59a97cdeae64f16a2272a9e7`<br/>`S_B == S_1 = 3bb4bcee...6e40ffee`<br/>`S_A == S_2 = 195d1b72...98215172` |
| **GB/T 38635.4** Part 4 App. A.1 (KEM) | `ec`, `pairing`, `kgc`, `enc`, root, `cmd/main` | `ID_B = "Bob"`, `hid = 0x03`, `klen = 32`, `ke = 0001edee...cede1c22`, `r = 00007401...684a6722` | `C1.x = 1edee2c3...aaac8a0f`<br/>`K = 4ff5cf86d2ad40c8f4bac98d76abdbde0c0e2f0a829d3f911ef5b2bce0695480` |
| **GB/T 38635.4** Part 4 App. A.2 (KDF-XOR PKE) | `enc`, root, `cmd/main` | `ID_B = "Bob"`, `M = "Chinese IBE standard"`, `r = 0000aac0...ec9e785c`, `EncMode::KdfXor` | `C1.x = 24454711...ac07d8ff`<br/>`C2 = 1b5f5b0e951489682f3e64e1378cdd5da9513b1c`<br/>`C3 = ba672387bcd6de50...fee37a2b9db9f367`<br/>Full `C1\|\|C3\|\|C2` = 116B exact match |
| **GB/T 38635.4** Part 4 App. A.3 (SM4-ECB-PKCS#7 PKE) | `sm4`, `enc`, root, `cmd/main` | Same `ID_B`, `M`, `r`, `EncMode::Sm4EcbPkcs7` (`K1` 16B, `K2` 32B) | `C2 = e05b6fac6f11b965268c994f00dba7a8bb00fd60583546cbdf4649250863f10a`<br/>`C3 = fd3c98dd92c44c68...01149d12b394a2be`<br/>Full `C1\|\|C3\|\|C2` = 128B exact match |

---

## 3. Algebraic Properties & Bilinear Identities Checklist

Beyond fixed test vectors, the test suite asserts mathematical invariants over deterministic non-trivial scalars and boundary cases:

- **Wide Arithmetic & Modular Field Axioms (`field`)**:
  - `adc`/`sbb`/`mac` carry/borrow saturation boundaries (`0xFFFF_FFFF_FFFF_FFFFUL` overflow paths) and $> 2^{256}$ intermediate reductions.
  - Associativity, commutativity, distributivity, and multiplicative inverse roundtrips ($a \cdot a^{-1} = 1$) across `Fp`, `Fn`, `Fp2`, `Fp6`, and `Fp12`.
  - Frobenius endomorphism correctness: `f.frobenius_p() == f.pow_u256(modulus_p)` and all 13 precomputed Montgomery Frobenius constants verified against direct exponentiation.
  - Fast-path equivalence: `Fp12::mul_by_014` matches dense `Fp12::mul`; Granger-Scott `cyclotomic_sqr` matches dense `Fp12::sqr` on $G_{\Phi_6}(\mathbb{F}_{p^2})$; `cyclotomic_pow_t` matches `pow_u256(U256::from_u64(BN_T))`.
- **Elliptic Curve Group Axioms (`ec`)**:
  - $P_1 \in E(\mathbb{F}_p)$ and $[N]P_1 = \mathcal{O}$; $P_2 \in E'(\mathbb{F}_{p^2})$ and $[N]P_2 = \mathcal{O}$.
  - Exceptional Jacobian addition cases: $P + \mathcal{O} = P$, $\mathcal{O} + P = P$, $P + P = [2]P$, $P + (-P) = \mathcal{O}$, and `add` vs `add_mixed` equivalence.
  - Multi-format encoding roundtrips: `G1` 64B raw / 65B uncompressed / 33B compressed (`0x02`/`0x03` via `Fp::sqrt`); `G2` 128B raw / 129B uncompressed.
- **Bilinear Pairing Identities (`pairing`, root)**:
  - Non-degeneracy: $e(P_2, P_1) \neq 1$.
  - Prime target-group order: $e(P_2, P_1)^N = 1$.
  - Full bilinearity: $e([a]P_2, [b]P_1) = e(P_2, P_1)^{ab} = e([b]P_2, [a]P_1) = e([ab]P_2, P_1) = e(P_2, [ab]P_1)$.
  - Left & right additivity: $e(Q, P_a + P_b) = e(Q, P_a) \cdot e(Q, P_b)$ and $e(Q_a + Q_b, P) = e(Q_a, P) \cdot e(Q_b, P)$.
  - Inversion via conjugation: $e(-P_2, P_1) = e(P_2, P_1)^{p^6} = \overline{e(P_2, P_1)}$.
  - Joint multi-pairing equivalence: `pair_product_coords(Q1, P1, Q2, P2) == e(Q1, P1) * e(Q2, P2)` (including infinity edge cases).
  - KGC protocol invariants: $e([H_1(\text{ID} \parallel \texttt{0x01})]P_2 + P_{\text{pub-s}}, ds_A) = e(P_{\text{pub-s}}, P_1)$ and $e(de_B, [H_1(\text{ID} \parallel \texttt{0x03})]P_1 + P_{\text{pub-e}}) = e(P_2, P_{\text{pub-e}})$.

---

## 4. Adversarial & Malformed Input Test Matrix

| Attack / Malformed Input Category | Tested Target(s) | Expected & Verified Behavior |
|---|---|---|
| **Non-canonical field coordinates ($\ge p$)** | `Fp::from_be_bytes_strict`, `Fp2`, all 12 slots of `Fp12`, `G1`/`G2` codecs | Strictly returns `None` (no silent wrap-around). |
| **Non-canonical / zero scalars ($0$ or $\ge N$)** | `Fn::from_be_bytes_strict`, `from_be_bytes_nonzero`, KGC master keys, `sign_with_r`, `keyex`, `enc` | Rejected with `None` or `Err(...)`. |
| **Off-curve $\mathbb{G}_1$ / $\mathbb{G}_2$ points** | `ec`, `kgc`, `sign`, `keyex`, `enc` | Rejected by `is_on_curve` check in `from_coords_checked` and strict decoders. |
| **Wrong sextic twist ($y^2 = x^3 + 5/u$)** | `ec`, `kgc` | Rejected as off-curve on $y^2 = x^3 + 5u$. |
| **$\mathbb{G}_2$ small-subgroup / cofactor point** | `ec` (`ec_wbtest.mbt` + blackbox), `kgc`, `sign`, `keyex`, `enc` | Point satisfies $y^2 = x^3 + 5u$ (`is_on_curve() == true`) but $[N]Q \neq \mathcal{O}$ (`is_in_subgroup() == false`); strictly rejected by all public constructors/decoders; clearing via $[h_2]Q$ confirmed to enter $\mathbb{G}_2$. |
| **Point at infinity / all-zero bytes** | `G1`/`G2` strict decoders, `kgc`, `sign`, `keyex`, `enc` | Rejected wherever a finite subgroup point is required. |
| **Invalid compressed/uncompressed prefixes & non-residue $x^3 + 5$** | `G1Affine::from_bytes_uncompressed_strict`, `from_bytes_compressed_strict` | Non-`0x04` / non-`0x02`/`0x03` prefix and quadratic non-residue $x$ return `None`. |
| **KGC singular master key ($t_1 \equiv 0 \pmod N$)** | `kgc::extract_*_private_key` | Explicitly returns `Err(...)` per GB/T 38635 specification. |
| **Signature forgery & domain tampering** | `sign::verify`, `sign::verify_precomputed` | Tampered message, altered `h`, altered `S`, wrong signer ID, mismatched `hid`, or malformed 96B/97B signature returns `false` / `None`. |
| **Key-exchange tampering & role confusion** | `keyex::initiator_exchange`, `verify_responder_confirmation` | Tampered `S_B`, tampered `S_A`, swapped `ID_A`/`ID_B`, infinity `R_A`/`R_B`, or `klen <= 0` rejected. |
| **Ciphertext truncation, MAC tampering & mode mismatch** | `enc::decrypt` | Ciphertext `< 96` bytes, bit-flipped `C1`, bit-flipped `C3`, bit-flipped `C2`, wrong recipient key/ID, or `KdfXor` vs `Sm4EcbPkcs7` mismatch rejected before plaintext release. |
| **SM4 PKCS#7 padding oracle tampering** | `sm4::decrypt_ecb_pkcs7`, `enc::decrypt` | Empty/non-16B-multiple ciphertext, pad `0x00`/`0x11`/`0xff`, single-byte corruption at every offset for all pad lengths `2..16`, and last-block bit-flips rejected in constant time (`None`). |

---

## 5. Package Unit Test Inventory & Multi-Target `-d` Verification

Each of the 9 core library packages is independently verified with `-d` (zero warnings, zero errors) across targets:

| Package | Verified Sub-Package Tests | Key Coverage |
|---|---|---|
| `sm3` | 10 (9 blackbox + 1 whitebox) | GB/T 32905 App. A.1/A.2, empty/block boundaries (55..128B), streaming/reset, `KDF`, `MAC` order, `H1`/`H2` 320-bit reduction & cross-limb boundaries, `ct_eq_bytes` |
| `sm4` | 5 | GB/T 32907 App. A.1, GB/T 38635.4 App. A.3, 0..48B PKCS#7 boundaries, invalid lengths, exhaustive padding-tampering checks |
| `field` | 9 | `adc`/`sbb`/`mac` overflow, `Fp`/`Fn`/`Fp2`/`Fp6`/`Fp12` axioms, 13 Frobenius constants, `mul_by_014`, `cyclotomic_sqr`, `cyclotomic_pow_t`, 384B `FE2OS` roundtrip & `>= p` rejection |
| `ec` | 9 (blackbox + whitebox) | `P1`/`P2` generators & order `N`, Part 2/3/4 official scalar-mul vectors, all codec formats, off-curve/`5/u`/cofactor attacks & `[h2]Q` cofactor clearing |
| `pairing` | 5 | All 7 official 384B pairing vectors (`e(P2,P1)`, Part 2 `g`, Part 3 `g1`/`g2`/`g3`, Part 4 `g`/`w`), order `N`, bilinearity, joint `pair_product_coords` |
| `kgc` | 7 | Part 2/3/4 official master & user keys, `t1 == 0` error path, `from_seed` domain separation, strict codecs & adversarial point rejection |
| `sign` | 6 | Part 2 App. A official vector, `verify` & `verify_precomputed`, deterministic signing & entropy separation, custom `hid`, 96B/97B codecs, forgery attacks |
| `keyex` | 4 | Part 3 App. A official handshake (`SK`, `S_B==S_1`, `S_A==S_2`), 16/32/64B handshakes, tampered tags & swapped IDs |
| `enc` | 6 | Part 4 App. A.1 (KEM), A.2 (KDF-XOR), A.3 (SM4-ECB-PKCS#7), empty/block-boundary/long plaintexts, tampering/truncation/off-curve/mode-mismatch |
| Root `moonsm9` | 7 (6 blackbox + 1 whitebox) | Full E2E GB/T 38635.2/.3/.4 Appendix A via facade, bilinearity property suite, adversarial malformed/forgery matrix |
| `cmd/main` | 3 + 6-stage CLI selftest | CLI command dispatch (`selftest`, `sm3`, `keygen`, `sign`, `keyex`, `encrypt`, `help`) & built-in 6-stage GB/T 38635-2020 selftest |
| **Total** | **71 unit/integration tests + 13 benchmarks** | **0 errors, 0 warnings (`-d`) across `wasm`, `wasm-gc`, `js`, and `native`** |

### Reproducible Multi-Target Verification Commands

```bash
# Formatting & generated .mbti interface check
moon fmt --check
moon info && git diff --exit-code -- '*.mbti'

# Full test suite with zero-warning enforcement (-d) across all 4 targets
moon test --target wasm -d
moon test --target wasm-gc -d
moon test --target js -d
moon test --target native -d

# Built-in 6-stage GB/T 38635-2020 CLI selftest across 3 targets
moon run cmd/main --target wasm-gc
moon run cmd/main --target js
moon run cmd/main --target native
```

---

## 6. Performance Benchmarks (`moon bench --release`)

`moonsm9` includes a reproducible `moon bench` microbenchmark suite covering core primitives and full SM9 protocol operations across `wasm-gc`, `js`, and `native`.

### Reproduce Locally

```bash
moon bench --release --target native
moon bench --release --target wasm-gc
moon bench --release --target js
```

### Measured Results

Measured on Windows x86\_64 with `moonc v0.10.22+124d61d05 (2026-11-19)`, `moonrun 0.1.20261119`, and Node.js `v22.16.0` (`moon bench -p CoolrfulDARkness/moonsm9 --release --target <target>`):

| Operation (`bench_test.mbt`) | `wasm-gc` (`--release`) | `native` (`--release`) | `js` (`--release`) |
|---|---|---|---|
| `sm3_64b` (SM3 64 B) | `810.00 ns ± 28.40 ns` | `881.75 ns ± 29.46 ns` | `2.12 µs ± 20.43 ns` |
| `sm3_1kb` (SM3 1 KiB) | `6.15 µs ± 134.54 ns` | `5.83 µs ± 154.19 ns` | `12.14 µs ± 313.15 ns` |
| `fp12_mul` ($\mathbb{F}_{p^{12}}$ mul) | `12.56 µs ± 391.05 ns` | `322.52 µs ± 8.95 µs` | `726.33 µs ± 36.81 µs` |
| `fp12_cyclotomic_sqr` (Granger-Scott sqr) | `4.55 µs ± 55.79 ns` | `107.45 µs ± 6.08 µs` | `288.94 µs ± 22.67 µs` |
| `g1_scalar_mul` (256-bit constant-time) | `589.78 µs ± 14.12 µs` | `15.94 ms ± 1.05 ms` | `99.48 ms ± 47.92 ms` |
| `g2_scalar_mul` (256-bit constant-time) | `1.78 ms ± 21.37 µs` | `44.29 ms ± 2.16 ms` | `121.61 ms ± 5.85 ms` |
| `rate_pairing` (Optimal R-ate $e(P_2, P_1)$) | `3.19 ms ± 86.47 µs` | `78.82 ms ± 5.68 ms` | `175.71 ms ± 11.91 ms` |
| `sm9_sign` (Part 2 Sign) | `10.02 ms ± 421.92 µs` | `251.77 ms ± 21.08 ms` | `519.68 ms ± 9.77 ms` |
| `sm9_verify` (Part 2 Verify) | `15.64 ms ± 236.89 µs` | `652.21 ms ± 544.97 ms` | `794.48 ms ± 19.05 ms` |
| `sm9_keyex_roundtrip` (Part 3 Responder + Initiator) | `33.28 ms ± 1.27 ms` | `862.51 ms ± 60.18 ms` | `1.88 s ± 227.92 ms` |
| `sm9_kem_encap_decap` (Part 4 KEM Encap + Decap) | `13.50 ms ± 339.18 µs` | `360.63 ms ± 13.03 ms` | `747.85 ms ± 51.47 ms` |
| `sm9_encrypt_decrypt_xor` (Part 4 A.2 KDF-XOR) | `14.83 ms ± 968.40 µs` | `589.88 ms ± 384.74 ms` | `870.27 ms ± 98.50 ms` |
| `sm9_encrypt_decrypt_sm4` (Part 4 A.3 SM4-ECB-PKCS#7) | `15.38 ms ± 421.68 µs` | `344.32 ms ± 13.99 ms` | `784.42 ms ± 49.15 ms` |

> **Backend Note**: On `wasm-gc`, MoonBit's unboxed 64-bit Wasm-GC codegen under `moonrun` JIT executes a full BN256 R-ate pairing in **3.19 ms** and a 256-bit constant-time `G1` scalar multiplication in **589.78 µs** with zero FFI. On `js`, `UInt64` operations are emulated via 32-bit pairs/BigInt overhead in V8. On Windows `native`, MoonBit v0.10.22 links via MSVC runtime; see `bench_test.mbt` to reproduce on Linux `gcc -O2` as well.

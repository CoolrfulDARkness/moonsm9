# CoolrfulDARkness/moonsm9

> [!IMPORTANT]
> **项目已架构整合至统一国密全栈仓库 [`CoolrfulDARkness/moontlcp`](https://github.com/CoolrfulDARkness/moontlcp)（`sm9/` 子包体系，commit `8bebbfe`）。**  
> 本仓库现仅保留作历史归档，不再单独维护或单独参评；合并版本已彻底消除重复 SM3/SM4 实现，与 TLCP 1.1（GM/T 0024）统一复用底层 `crypto/sm3`、`crypto/sm4`、`crypto/ct` 恒定时间原语。  
> **Consolidated into [`CoolrfulDARkness/moontlcp`](https://github.com/CoolrfulDARkness/moontlcp):** This repository is archived for historical reference. All GB/T 38635-2020 SM9 packages now live under `moontlcp/sm9` sharing the unified `crypto/sm3`, `crypto/sm4`, and `crypto/ct` core.

**Pure MoonBit, zero-FFI, bit-identical multi-target SM9 Identity-Based Cryptographic Algorithms suite (`GB/T 38635-2020` / `GM/T 0044-2016`), with built-in SM3 (`GB/T 32905-2016`) and SM4 (`GB/T 32907-2016`).**

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

---

## Highlights

- **100% Pure MoonBit, Zero FFI, Zero Third-Party Dependencies**: Compiles and produces bit-identical results across `wasm`, `wasm-gc`, `js`, and `native` using only `moonbitlang/core`.
- **Complete GB/T 38635-2020 Suite**:
  - **Part 1 & 5**: BN256 curve ($E(\mathbb{F}_p): y^2 = x^3 + 5$, D-type twist $E'(\mathbb{F}_{p^2}): y^2 = x^3 + 5u$), `FE2OS`/`EC2OS`, `H1`/`H2`, `KDF`, `MAC`, SM3, and SM4-ECB-PKCS#7.
  - **Part 2**: Identity-Based Digital Signature (KGC key extraction, deterministic & explicit-nonce signing, verification, precomputed pairing `g`).
  - **Part 3**: Authenticated Key Exchange Protocol with mutual key confirmation (`S_B == S_1`, `S_A == S_2`).
  - **Part 4**: Key Encapsulation Mechanism (KEM) and Public-Key Encryption in both **KDF-XOR** (Appendix A.2) and **SM4-ECB-PKCS#7** (Appendix A.3) modes with MAC-then-decrypt (`C1 || C3 || C2`).
- **High-Performance Pairing & Constant-Time Cryptography**:
  - 4×64-bit CIOS Montgomery arithmetic with overflow-free 32×32→64 `mac` splitting.
  - Zero-cost basis permutation between internal $\mathbb{F}_p \to \mathbb{F}_{p^2} \to \mathbb{F}_{p^6} \to \mathbb{F}_{p^{12}}$ tower and standard GB/T 38635 384-byte `FE2OS`.
  - Constant-time 4-bit fixed-window Jacobian scalar multiplication with complete branchless addition and mandatory $\mathbb{G}_2$ prime-order subgroup validation against cofactor attacks.
  - Zero-inversion Jacobian R-ate Miller loop (66-bit `6t + 2` NAF, 11 non-zero terms, sparse `mul_by_014`) + Fuentes-Castaneda cyclotomic final exponentiation (only 3 `cyclotomic_pow_t`) + joint two-pair `pair_product_coords`.
- **100% Official Test Vector Verified & Zero-Warning (`-d`)**: Every official test vector from GB/T 32905, GB/T 32907, and GB/T 38635 Parts 2, 3, and 4 (A.1 / A.2 / A.3) passes byte-for-byte across all targets with `-d` zero-warning enforcement.

---

## Package Structure

| Package | Description |
|---|---|
| `CoolrfulDARkness/moonsm9` | Unified high-level SM9 facade package |
| `CoolrfulDARkness/moonsm9/sm3` | SM3 cryptographic hash, `KDF`, `MAC` (`SM3(C2 \|\| K2)`), `H1`/`H2`, `ct_eq_bytes`, hex codec |
| `CoolrfulDARkness/moonsm9/sm4` | SM4 128-bit block cipher and constant-time validated `SM4-ECB-PKCS#7` |
| `CoolrfulDARkness/moonsm9/field` | `U256`, scalar field `Fn`, 4×64-bit Montgomery `Fp`, extension tower `Fp2`/`Fp6`/`Fp12`, Frobenius constants |
| `CoolrfulDARkness/moonsm9/ec` | BN256 `G1` & `G2` affine/Jacobian groups, constant-time scalar mul, `G2` subgroup check, strict codecs |
| `CoolrfulDARkness/moonsm9/pairing` | Optimal R-ate bilinear pairing (`miller_loop`, `final_exponentiation`, `pair_coords`, `pair_product_coords`) |
| `CoolrfulDARkness/moonsm9/kgc` | KGC master key management and user private key extraction (`HID_SIGN`, `HID_KEYEX`, `HID_ENC`) |
| `CoolrfulDARkness/moonsm9/sign` | GB/T 38635.2 SM9 digital signature & verification |
| `CoolrfulDARkness/moonsm9/keyex` | GB/T 38635.3 SM9 key exchange with mutual confirmation |
| `CoolrfulDARkness/moonsm9/enc` | GB/T 38635.4 SM9 KEM & public-key encryption (`KdfXor` / `Sm4EcbPkcs7`) |
| `CoolrfulDARkness/moonsm9/cmd/main` | Standalone multi-target CLI demo & built-in 6-stage GB/T 38635-2020 selftest |

---

## Quick Start

### 1. Run the Full Multi-Target Test Suite (`-d` Zero Warnings)

```bash
moon test --target wasm -d
moon test --target wasm-gc -d
moon test --target js -d
moon test --target native -d
```

### 2. Run the Built-In CLI Selftest & Interactive Commands

```bash
# Default subcommand runs all 6 GB/T 38635-2020 verification suites
moon run cmd/main --target wasm
moon run cmd/main --target wasm-gc
moon run cmd/main --target js
moon run cmd/main --target native

# Interactive CLI subcommands
moon run cmd/main -- sm3 "abc"
moon run cmd/main -- sign "master-seed" "Alice" "Hello SM9"
moon run cmd/main -- keyex "master-seed" "Alice" "Bob"
moon run cmd/main -- encrypt "master-seed" "Bob" "Hello IBE" sm4
```

### 3. Run Release Benchmarks Across Targets

```bash
moon bench --release --target wasm-gc
moon bench --release --target native
moon bench --release --target js
```

Selected measured results (`moonc v0.10.22`, `moon bench --release`):

| Operation | `wasm-gc` | `native` | `js` |
|---|---|---|---|
| `sm3_64b` | `810.00 ns` | `881.75 ns` | `2.12 µs` |
| `fp12_cyclotomic_sqr` | `4.55 µs` | `107.45 µs` | `288.94 µs` |
| `g1_scalar_mul` (256-bit CT) | `589.78 µs` | `15.94 ms` | `99.48 ms` |
| `g2_scalar_mul` (256-bit CT) | `1.78 ms` | `44.29 ms` | `121.61 ms` |
| `rate_pairing` ($e(P_2, P_1)$) | `3.19 ms` | `78.82 ms` | `175.71 ms` |
| `sm9_sign` | `10.02 ms` | `251.77 ms` | `519.68 ms` |
| `sm9_verify` | `15.64 ms` | `652.21 ms` | `794.48 ms` |
| `sm9_kem_encap_decap` | `13.50 ms` | `360.63 ms` | `747.85 ms` |
| `sm9_encrypt_decrypt_sm4` | `15.38 ms` | `344.32 ms` | `784.42 ms` |

See [`docs/VERIFICATION.md`](docs/VERIFICATION.md) for all 13 benchmark entries and full methodology.

### 4. Minimal Usage Example

Add `CoolrfulDARkness/moonsm9` to your `moon.mod` and import the sub-packages (or the root facade) in your `moon.pkg`.

> **Entropy Requirement**: Because `moonsm9` has zero OS FFI, callers must supply fresh cryptographic randomness from an external CSPRNG. In particular, SM9 KEM (`kem_encapsulate_deterministic`) and PKE (`encrypt_deterministic`) strictly require **at least 32 bytes** of fresh CSPRNG entropy per operation.

```moonbit nocheck
// --- Part 2: SM9 Digital Signature ---

///|
let sign_msk = @kgc.SignMasterPrivateKey::from_seed(
  b"demo-sign-master-seed-32bytes!!!",
)

///|
let sign_mpk = sign_msk.public_key()

///|
let alice_sk = @kgc.extract_sign_private_key(sign_msk, b"Alice").unwrap()

///|
let sig = @sign.sign_deterministic(
  sign_mpk.to_g2(),
  alice_sk.to_g1(),
  b"Hello MoonBit SM9",
  b"fresh-nonce-entropy",
).unwrap()

///|
let ok = @sign.verify(sign_mpk.to_g2(), b"Alice", b"Hello MoonBit SM9", sig)

// --- Part 4: SM9 Public-Key Encryption (SM4-ECB-PKCS#7) ---

///|
let enc_msk = @kgc.EncMasterPrivateKey::from_seed(
  b"demo-enc-master-seed-32bytes!!!!",
)

///|
let enc_mpk = enc_msk.public_key()

///|
let bob_sk = @kgc.extract_enc_private_key(enc_msk, b"Bob").unwrap()

///|
// KEM and PKE require >= 32 bytes of fresh CSPRNG entropy per operation.
let ct = @enc.encrypt_deterministic(
  enc_mpk.to_g1(),
  b"Bob",
  b"Confidential payload",
  b"fresh-32byte-csprng-enc-entropy!",
  mode=@enc.EncMode::Sm4EcbPkcs7,
).unwrap()

///|
let pt = @enc.decrypt(
  b"Bob",
  bob_sk.to_g2(),
  ct,
  mode=@enc.EncMode::Sm4EcbPkcs7,
).unwrap()
```

---

## Documentation

- **[Architecture & Mathematical Design](docs/ARCHITECTURE.md)** — Layered 11-package architecture, BN256 parameters, 4×64-bit Montgomery arithmetic, zero-cost tower basis isomorphism, constant-time Jacobian EC groups, zero-inversion R-ate pairing, interoperability rules, and security boundaries.
- **[Verification, Test Vectors & Benchmarks](docs/VERIFICATION.md)** — Independent Python 3 mathematical reference methodology, GB/T 38635-2020 Appendix A coverage matrix, bilinear identities, adversarial input testing, and release benchmark tables.

---

## License

Licensed under the **Apache License, Version 2.0**. See [LICENSE](LICENSE) for details.

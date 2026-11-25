///|
fn join_lines(lines : Array[String]) -> String {
  let mut acc = ""
  for i = 0; i < lines.length(); i = i + 1 {
    if i > 0 {
      acc = acc + "\n"
    }
    acc = acc + lines[i]
  }
  acc
}

///|
test "CLI extract_subcommand_args handles empty, prog-only, prog+cmd, JS runtimes, and raw cmd" {
  assert_eq(extract_subcommand_args([]), [])
  assert_eq(extract_subcommand_args(["./main.exe"]), [])
  assert_eq(extract_subcommand_args(["./main.exe", "sm3", "abc"]), [
    "sm3", "abc",
  ])
  // Native/non-JS executable must NOT swallow .js/.mjs/.cjs/.wasm user arguments
  assert_eq(extract_subcommand_args(["./main.exe", "foo.js"]), ["foo.js"])
  assert_eq(extract_subcommand_args(["./main.exe", "foo.wasm"]), ["foo.wasm"])
  assert_eq(extract_subcommand_args(["./main.exe", "sm3", "foo.js"]), [
    "sm3", "foo.js",
  ])
  // Case-insensitive JS runtime basename + case-insensitive .js/.mjs/.cjs script skipping
  assert_eq(extract_subcommand_args(["node.exe", "D:\\app\\main.js"]), [])
  assert_eq(extract_subcommand_args(["node.exe", "D:\\app\\MAIN.JS"]), [])
  assert_eq(
    extract_subcommand_args(["node.exe", "D:\\app\\MAIN.JS", "sm3", "abc"]),
    ["sm3", "abc"],
  )
  assert_eq(
    extract_subcommand_args([
      "C:\\Program Files\\nodejs\\NODE.EXE", "D:\\app\\MAIN.MJS", "help",
    ]),
    ["help"],
  )
  assert_eq(
    extract_subcommand_args(["/usr/local/bin/deno", "/tmp/cli.CJS", "sm3", "x"]),
    ["sm3", "x"],
  )
  assert_eq(extract_subcommand_args(["/opt/bun/BUN", "entry.js", "selftest"]), [
    "selftest",
  ])
  assert_eq(extract_subcommand_args(["bun.exe", "entry.wasm"]), ["entry.wasm"])
  assert_eq(extract_subcommand_args(["selftest"]), ["selftest"])
  assert_eq(extract_subcommand_args(["help"]), ["help"])
}

///|
test "CLI selftest passes all 6 GB/T 38635-2020 suites" {
  let lines = match execute_cli([]) {
    Ok(out) => out
    Err(e) => fail("selftest failed: " + e)
  }
  let report = join_lines(lines)
  assert_true(
    report.contains("[PASS] All 6 GB/T 38635-2020 verification suites passed!"),
  )
}

///|
test "CLI subcommands: sm3, keygen, sign, keyex, encrypt (xor & sm4), help" {
  // sm3
  let sm3_out = match execute_cli(["sm3", "abc"]) {
    Ok(out) => join_lines(out)
    Err(e) => fail("sm3 cmd failed: " + e)
  }
  assert_true(
    sm3_out.contains(
      "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0",
    ),
  )

  // keygen
  let kg_out = match execute_cli(["keygen", "demo-seed", "alice@example.com"]) {
    Ok(out) => join_lines(out)
    Err(e) => fail("keygen cmd failed: " + e)
  }
  assert_true(kg_out.contains("P_pub-s"))
  assert_true(kg_out.contains("de_keyex"))

  // sign
  let sign_out = match
    execute_cli(["sign", "demo-seed", "Alice", "Hello SM9 Signature"]) {
    Ok(out) => join_lines(out)
    Err(e) => fail("sign cmd failed: " + e)
  }
  assert_true(sign_out.contains("Verify    : PASS"))

  // keyex
  let kx_out = match execute_cli(["keyex", "demo-seed", "Alice", "Bob"]) {
    Ok(out) => join_lines(out)
    Err(e) => fail("keyex cmd failed: " + e)
  }
  assert_true(kx_out.contains("[CONFIRMED]"))

  // encrypt (default xor)
  let enc_xor = match
    execute_cli(["encrypt", "demo-seed", "Bob", "Secret XOR msg"]) {
    Ok(out) => join_lines(out)
    Err(e) => fail("encrypt xor cmd failed: " + e)
  }
  assert_true(enc_xor.contains("Decrypted    : Secret XOR msg"))
  assert_true(enc_xor.contains("Round-Trip   : PASS"))

  // encrypt (sm4)
  let enc_sm4 = match
    execute_cli(["encrypt", "demo-seed", "Bob", "Secret SM4 msg", "sm4"]) {
    Ok(out) => join_lines(out)
    Err(e) => fail("encrypt sm4 cmd failed: " + e)
  }
  assert_true(enc_sm4.contains("SM4-ECB-PKCS#7"))
  assert_true(enc_sm4.contains("Decrypted    : Secret SM4 msg"))
  assert_true(enc_sm4.contains("Round-Trip   : PASS"))

  // help
  let help_out = match execute_cli(["--help"]) {
    Ok(out) => join_lines(out)
    Err(e) => fail("help cmd failed: " + e)
  }
  assert_true(help_out.contains("selftest"))
  assert_true(help_out.contains("encrypt"))

  // error cases: unknown command, missing args, invalid mode, and trailing extra args
  assert_true(execute_cli(["unknown-cmd"]) is Err(_))
  assert_true(execute_cli(["selftest", "extra"]) is Err(_))
  assert_true(execute_cli(["help", "extra"]) is Err(_))
  assert_true(execute_cli(["--help", "extra"]) is Err(_))
  assert_true(execute_cli(["-h", "extra"]) is Err(_))
  assert_true(execute_cli(["sm3"]) is Err(_))
  assert_true(execute_cli(["sm3", "abc", "extra"]) is Err(_))
  assert_true(execute_cli(["keygen", "s"]) is Err(_))
  assert_true(execute_cli(["keygen", "s", "id", "extra"]) is Err(_))
  assert_true(execute_cli(["sign", "s", "id"]) is Err(_))
  assert_true(execute_cli(["sign", "s", "id", "m", "extra"]) is Err(_))
  assert_true(execute_cli(["keyex", "s", "a"]) is Err(_))
  assert_true(execute_cli(["keyex", "s", "a", "b", "extra"]) is Err(_))
  assert_true(execute_cli(["encrypt", "s", "id"]) is Err(_))
  assert_true(execute_cli(["encrypt", "s", "id", "m", "invalid"]) is Err(_))
  assert_true(
    execute_cli(["encrypt", "s", "id", "m", "sm4", "extra"]) is Err(_),
  )
}

///|
test "CLI sm3_domain_hash prevents field boundary ambiguity" {
  let h1 = sm3_domain_hash(b"moonsm9:cli:keyex:A:v1", [b"ab", b"c", b"d"])
  let h2 = sm3_domain_hash(b"moonsm9:cli:keyex:A:v1", [b"a", b"bc", b"d"])
  assert_eq(h1.length(), 32)
  assert_eq(h2.length(), 32)
  assert_true(h1 != h2)
}

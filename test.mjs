import assert from "node:assert/strict";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const ioc = require("./ioc.js");

let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    passed += 1;
    console.log(`PASS  ${name}`);
  } catch (error) {
    failed += 1;
    console.error(`FAIL  ${name}`);
    console.error(`      ${error.message}`);
  }
}

function values(result, key) {
  return result[key].map((item) => item.value);
}

function byValue(result, key) {
  return Object.fromEntries(result[key].map((item) => [item.value, item.flags]));
}

test("IPv4 extraction and private/reserved flags", () => {
  const result = ioc.extract(
    "10.0.0.1 172.16.5.4 172.32.0.1 192.168.1.10 127.0.0.1 169.254.1.1 8.8.8.8 203.0.113.9"
  );
  const flags = byValue(result, "ipv4");
  assert.ok(flags["10.0.0.1"].includes("private"));
  assert.ok(flags["172.16.5.4"].includes("private"));
  assert.ok(!flags["172.32.0.1"].includes("private"));
  assert.ok(flags["192.168.1.10"].includes("private"));
  assert.ok(flags["127.0.0.1"].includes("loopback"));
  assert.ok(flags["169.254.1.1"].includes("link-local"));
  assert.deepEqual(flags["8.8.8.8"], []);
  assert.ok(flags["203.0.113.9"].includes("documentation"));
});

test("invalid IPv4 values are ignored", () => {
  const result = ioc.extract("256.1.1.1 1.2.3 999.999.999.999 01.02.03.04");
  assert.deepEqual(values(result, "ipv4"), []);
});

test("IPv6 extraction rejects timestamps and MAC addresses", () => {
  const result = ioc.extract(
    "2001:db8::1 fe80::1 ::1 12:34:56 aa:bb:cc:dd:ee:ff 2001:db8:0:0:0:0:2:1"
  );
  assert.deepEqual(
    values(result, "ipv6").sort(),
    ["2001:db8::1", "2001:db8:0:0:0:0:2:1", "::1", "fe80::1"].sort()
  );
  const flags = byValue(result, "ipv6");
  assert.ok(flags["fe80::1"].includes("link-local"));
  assert.ok(flags["::1"].includes("loopback"));
  assert.ok(flags["2001:db8::1"].includes("documentation"));
});

test("domains use a TLD allowlist and skip filenames", () => {
  const result = ioc.extract(
    "example.com sub.example.test report.pdf script.js update.exe README.md foo.bar foo.co.uk"
  );
  assert.deepEqual(values(result, "domains"), [
    "example.com",
    "sub.example.test",
    "foo.co.uk",
  ]);
});

test("URLs refang, trim punctuation, and keep IPv6 brackets", () => {
  const result = ioc.extract(
    "hxxps://login[.]example[.]com/reset?user=victim " +
      "hxxp://198[.]51[.]100[.]23/payload[.]bin " +
      "hxxp://example[.]com[:]8080/admin " +
      "(http://example.org/a). " +
      "http://[2001:db8::1]/health"
  );
  assert.deepEqual(values(result, "urls"), [
    "https://login.example.com/reset?user=victim",
    "http://198.51.100.23/payload.bin",
    "http://example.com:8080/admin",
    "http://example.org/a",
    "http://[2001:db8::1]/health",
  ]);
  assert.equal(
    result.urls[0].defanged,
    "hxxps://login[.]example[.]com/reset?user=victim"
  );
});

test("emails refang and reject filename-like TLDs", () => {
  const result = ioc.extract(
    "it-support[@]example[.]com analyst@example.test foo@bar.pdf USER@EXAMPLE.COM user@example.com"
  );
  assert.deepEqual(values(result, "emails"), [
    "it-support@example.com",
    "analyst@example.test",
    "user@example.com",
  ]);
});

test("hash lengths are classified without overlap", () => {
  const input = [
    "a".repeat(32),
    "b".repeat(40),
    "c".repeat(64),
    "d".repeat(31),
    "e".repeat(33),
    "f".repeat(41),
    "0".repeat(63),
    "1".repeat(65),
  ].join(" ");
  const result = ioc.extract(input);
  assert.equal(result.md5.length, 1);
  assert.equal(result.sha1.length, 1);
  assert.equal(result.sha256.length, 1);
  assert.equal(result.md5[0].value, "a".repeat(32));
  assert.equal(result.sha1[0].value, "b".repeat(40));
  assert.equal(result.sha256[0].value, "c".repeat(64));
});

test("hashes deduplicate case-insensitively", () => {
  const result = ioc.extract(`${"A".repeat(32)} ${"a".repeat(32)}`);
  assert.equal(result.md5.length, 1);
  assert.equal(result.md5[0].value, "a".repeat(32));
});

test("CVEs and ATT&CK IDs normalize and deduplicate", () => {
  const result = ioc.extract(
    "cve-2024-3400 CVE-2021-44228 CVE-2024-3400 T1059 T1059.001 t1110 T1059.001"
  );
  assert.deepEqual(values(result, "cves"), ["CVE-2024-3400", "CVE-2021-44228"]);
  assert.deepEqual(values(result, "attack"), ["T1059", "T1059.001", "T1110"]);
});

test("refang handles common defanged forms", () => {
  assert.equal(
    ioc.refang("hxxps://login[.]example[.]com[:]8443/a[at]b"),
    "https://login.example.com:8443/a@b"
  );
  assert.equal(
    ioc.refang("hxxp://198[.]51[.]100[.]23/x"),
    "http://198.51.100.23/x"
  );
  assert.equal(ioc.refang("user[@]example[.]com"), "user@example.com");
});

test("defang output is safe to share", () => {
  assert.equal(
    ioc.defang("http://example.com/a?b=1", "url"),
    "hxxp://example[.]com/a?b=1"
  );
  assert.equal(
    ioc.defang("https://example.com", "url"),
    "hxxps://example[.]com"
  );
  assert.equal(
    ioc.defang("user@example.com", "email"),
    "user[@]example[.]com"
  );
  assert.equal(ioc.defang("192.0.2.1", "ipv4"), "192[.]0[.]2[.]1");
  assert.equal(ioc.defang("2001:db8::1", "ipv6"), "2001[:]db8[:][:]1");
  assert.equal(ioc.defang("example.com", "domain"), "example[.]com");
});

test("timestamps and version-like strings do not create false positives", () => {
  const result = ioc.extract("12:34:56 1.2.3.4-beta report.pdf script.js");
  assert.deepEqual(values(result, "ipv6"), []);
  assert.deepEqual(values(result, "domains"), []);
  assert.deepEqual(values(result, "ipv4"), ["1.2.3.4"]);
});

test("repeated indicators are deduplicated", () => {
  const result = ioc.extract("1.1.1.1 1.1.1.1 EXAMPLE.COM example.com");
  assert.equal(result.ipv4.length, 1);
  assert.equal(result.domains.length, 1);
});

test("empty input returns empty groups", () => {
  const result = ioc.extract("");
  assert.equal(ioc.countAll(result), 0);
  ioc.TYPE_META.forEach((meta) => {
    assert.equal(result[meta.key].length, 0);
  });
});

test("the bundled sample is realistic and parses", () => {
  const result = ioc.extract(ioc.SAMPLE_TEXT);
  assert.ok(result.ipv4.length >= 4);
  assert.ok(result.ipv6.length >= 2);
  assert.ok(result.domains.length >= 3);
  assert.ok(result.urls.length >= 3);
  assert.ok(result.emails.length >= 2);
  assert.equal(result.md5.length, 1);
  assert.equal(result.sha1.length, 1);
  assert.equal(result.sha256.length, 1);
  assert.ok(result.cves.length >= 2);
  assert.ok(result.attack.length >= 3);
  assert.ok(result.ipv6.every((item) => item.value !== "03:14:22"));
});

console.log(`\n${passed} passed, ${failed} failed.`);
if (failed > 0) process.exitCode = 1;

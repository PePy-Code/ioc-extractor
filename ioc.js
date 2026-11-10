/* IOC Extractor — pure extraction core + browser UI.
   UMD-ish so `extract()` can be imported by Node tests and loaded as a
   classic <script> in the browser. No dependencies, no network calls. */
(function (root, factory) {
  "use strict";
  if (typeof module === "object" && module.exports) {
    module.exports = factory();
  } else {
    var api = factory();
    root.IOCExtractor = api;
    if (typeof document !== "undefined") {
      if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", api.initUI, { once: true });
      } else {
        api.initUI();
      }
    }
  }
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
  "use strict";

  var TYPE_META = [
    { key: "ipv4", label: "IPv4" },
    { key: "ipv6", label: "IPv6" },
    { key: "domains", label: "Domains" },
    { key: "urls", label: "URLs" },
    { key: "emails", label: "Emails" },
    { key: "md5", label: "MD5" },
    { key: "sha1", label: "SHA1" },
    { key: "sha256", label: "SHA256" },
    { key: "cves", label: "CVEs" },
    { key: "attack", label: "ATT&CK" },
  ];

  /* Common TLDs only. This is the main defence against report.pdf /
     script.js / update.exe being reported as domains. */
  var TLD_ALLOWLIST = new Set(
    (
      "com org net edu gov mil int info biz name pro mobi asia travel museum " +
      "aero coop jobs tel cat post io dev app ai co me tv cc ws xyz top online " +
      "site club shop store tech cloud security solutions systems network email " +
      "link live digital agency studio design software codes tools works world " +
      "today news blog wiki zone space website host press center academy " +
      "education training consulting services support company business global " +
      "group international management marketing media mobile money partner " +
      "properties realestate rentals social solar style supply tax team " +
      "technology tips ventures vision webcam art band beer coffee community " +
      "dance family farm fish fit fun games garden gifts graphics guru health " +
      "house ink land life love ltd menu ninja photo photography photos pizza " +
      "place plus pub recipes rocks run sale school science shoes show ski " +
      "soccer study surf tattoo taxi tennis theater tienda toys university uno " +
      "vacations vegas video villas vin vip vodka vote voyage watch wine work " +
      "yoga test example invalid onion " +
      "us uk mx es ar cl co pe br ca de fr it nl be ch at se no dk fi ie pt gr " +
      "tr ru ua pl cz sk hu ro bg hr si rs il ae sa qa kw eg za ng ke ma in pk " +
      "bd lk np cn jp kr tw hk sg my id th vn ph au nz eu"
    ).split(/\s+/)
  );

  /* Even when a file extension is also a real gTLD (zip, mov, …), prefer
     treating it as a filename to avoid noisy false positives. */
  var FILE_EXTENSIONS = new Set(
    (
      "pdf js mjs cjs jsx ts tsx css html htm xhtml txt md markdown json xml " +
      "yml yaml toml ini cfg conf log csv tsv doc docx xls xlsx ppt pptx odt " +
      "ods rtf png jpg jpeg gif bmp svg webp ico tif tiff psd ai eps mp3 wav " +
      "flac ogg m4a mp4 mkv avi mov wmv webm zip tar gz tgz bz2 xz 7z rar iso " +
      "bin exe dll so dylib apk deb rpm msi bat cmd ps1 sh bash zsh py rb pl " +
      "php java class jar war c h cpp hpp cc cs go rs swift kt kts scala lua " +
      "sql db sqlite bak tmp dat lock map min pem crt cer key pfx p12 env"
    ).split(/\s+/)
  );

  var SAMPLE_TEXT = [
    "Jan 12 03:14:22 web01.example.test sshd[4242]: Failed password for invalid user admin from 203.0.113.47 port 51234 ssh2",
    "Jan 12 03:14:25 web01.example.test sshd[4242]: Failed password for invalid user admin from 203.0.113.47 port 51235 ssh2",
    "Jan 12 03:14:31 web01.example.test sshd[4242]: Failed password for invalid user root from 203.0.113.47 port 51236 ssh2",
    "Jan 12 03:15:02 web01.example.test sshd[4242]: Accepted password for deploy from 10.0.0.15 port 44221 ssh2",
    "Jan 12 03:15:10 web01.example.test kernel: DROP IN=eth0 SRC=198.51.100.77 DST=192.0.2.10 PROTO=TCP SPT=443 DPT=51515",
    "Jan 12 03:15:12 fw01.example.test kernel: DROP IN=eth0 SRC=10.1.2.3 DST=192.0.2.10 PROTO=TCP SPT=4444 DPT=22",
    "Jan 12 03:16:00 web01.example.test systemd[1]: Started session for user analyst.",
    "",
    "From: \"IT Support\" <it-support[@]example[.]com>",
    "To: analyst@example[.]test",
    "Subject: Action required: verify your account",
    "Please sign in at hxxps://login[.]example[.]com/reset?user=victim and review report.pdf.",
    "Backup mirror: hxxp://198[.]51[.]100[.]23/payload[.]bin (do not open on production).",
    "Admin panel: hxxp://example[.]com[:]8080/admin",
    "C2 beacon observed to 2001:db8::42 and fe80::1 on the lab segment.",
    "File hash: 44d88612fea8a8f36de82e1278abb02f",
    "SHA1: 3395856ce81f2b7382dee72602f798b642f14140",
    "SHA256: 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
    "Detected CVE-2024-3400 and CVE-2021-44228; mapped to T1059.001, T1110 and T1566.002.",
    "Ignore these filenames: report.pdf, script.js, update.exe, notes.md.",
    "Timestamps like 03:14:22 must not be mistaken for IPv6.",
  ].join("\n");

  function emptyGroups() {
    return {
      ipv4: [],
      ipv6: [],
      domains: [],
      urls: [],
      emails: [],
      md5: [],
      sha1: [],
      sha256: [],
      cves: [],
      attack: [],
    };
  }

  function addUnique(list, seen, item, key) {
    var dedupeKey = key == null ? item.value.toLowerCase() : key;
    if (seen.has(dedupeKey)) return;
    seen.add(dedupeKey);
    list.push(item);
  }

  function refang(input) {
    return String(input == null ? "" : input)
      .replace(/\[dot\]|\(dot\)|\{dot\}|<dot>/gi, ".")
      .replace(/\[\.\]|\(\.\)|\{\.\}|<\.>/g, ".")
      .replace(/\[:\]|\(:\)|\{:\}/g, ":")
      .replace(/\[@\]|\(@\)|\{@\}|\[at\]|\(at\)|\{at\}/gi, "@")
      .replace(/\[:\/\/\]/g, "://")
      .replace(/\[\/\/\]/g, "//")
      .replace(/\bhxxps\b/gi, "https")
      .replace(/\bhxxp\b/gi, "http");
  }

  function defangValue(value, type) {
    if (type === "url") {
      return value
        .replace(/^https:/i, "hxxps:")
        .replace(/^http:/i, "hxxp:")
        .replace(/\./g, "[.]")
        .replace(/@/g, "[@]")
        .replace(/:(?!\/\/)/g, "[:]");
    }
    if (type === "domain") return value.replace(/\./g, "[.]");
    if (type === "email") return value.replace(/@/g, "[@]").replace(/\./g, "[.]");
    if (type === "ipv4") return value.replace(/\./g, "[.]");
    if (type === "ipv6") return value.replace(/:/g, "[:]");
    return value;
  }

  function defang(value, type) {
    return defangValue(String(value), type || "domain");
  }

  function isAllowedTld(tld) {
    var lower = String(tld).toLowerCase();
    return TLD_ALLOWLIST.has(lower) && !FILE_EXTENSIONS.has(lower);
  }

  function isValidIPv4(value) {
    var parts = value.split(".");
    if (parts.length !== 4) return false;
    for (var i = 0; i < parts.length; i += 1) {
      if (!/^(0|[1-9]\d{0,2})$/.test(parts[i])) return false;
      if (Number(parts[i]) > 255) return false;
    }
    return true;
  }

  function ipv4Flags(value) {
    var p = value.split(".").map(Number);
    var flags = [];
    if (
      p[0] === 10 ||
      (p[0] === 172 && p[1] >= 16 && p[1] <= 31) ||
      (p[0] === 192 && p[1] === 168)
    ) {
      flags.push("private");
    }
    if (p[0] === 127) flags.push("loopback");
    if (p[0] === 169 && p[1] === 254) flags.push("link-local");
    if (p[0] === 0) flags.push("reserved");
    if (p[0] === 100 && p[1] >= 64 && p[1] <= 127) flags.push("cgnat");
    if (
      (p[0] === 192 && p[1] === 0 && p[2] === 2) ||
      (p[0] === 198 && p[1] === 51 && p[2] === 100) ||
      (p[0] === 203 && p[1] === 0 && p[2] === 113)
    ) {
      flags.push("documentation");
    }
    if (p[0] === 198 && (p[1] === 18 || p[1] === 19)) flags.push("benchmark");
    if (p[0] >= 224 && p[0] <= 239) flags.push("multicast");
    if (p[0] >= 240) flags.push("reserved");
    if (value === "255.255.255.255") flags.push("broadcast");
    return flags;
  }

  function isValidIPv6(value) {
    if (!value || value.indexOf(":") === -1) return false;
    if ((value.match(/::/g) || []).length > 1) return false;
    var halves = value.split("::");
    var left = halves[0] ? halves[0].split(":") : [];
    var right = halves.length > 1 && halves[1] ? halves[1].split(":") : [];
    var groups = left.concat(right);
    for (var i = 0; i < groups.length; i += 1) {
      if (!/^[0-9a-fA-F]{1,4}$/.test(groups[i])) return false;
    }
    if (halves.length === 1) return groups.length === 8;
    return groups.length < 8;
  }

  function ipv6Flags(value) {
    var lower = value.toLowerCase();
    var flags = [];
    if (lower === "::1") flags.push("loopback");
    if (lower === "::") flags.push("unspecified");
    if (/^fe[89ab]/.test(lower)) flags.push("link-local");
    if (/^f[cd]/.test(lower)) flags.push("private");
    if (/^ff/.test(lower)) flags.push("multicast");
    if (lower.indexOf("2001:db8") === 0) flags.push("documentation");
    return flags;
  }

  function trimUrl(value) {
    var out = value.replace(/[.,;:!?]+$/g, "");
    var opens;
    var closes;
    if (out.charAt(out.length - 1) === ")") {
      opens = (out.match(/\(/g) || []).length;
      closes = (out.match(/\)/g) || []).length;
      if (closes > opens) out = out.slice(0, -1);
    }
    if (out.charAt(out.length - 1) === "]") {
      opens = (out.match(/\[/g) || []).length;
      closes = (out.match(/\]/g) || []).length;
      if (closes > opens) out = out.slice(0, -1);
    }
    return out;
  }

  function extractIPv4(text, groups, seen) {
    var re = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
    var match;
    while ((match = re.exec(text))) {
      var value = match[0];
      if (!isValidIPv4(value)) continue;
      var after = text.charAt(match.index + value.length);
      if (after === "." && /\d/.test(text.charAt(match.index + value.length + 1))) {
        continue;
      }
      addUnique(groups.ipv4, seen.ipv4, {
        value: value,
        defanged: defangValue(value, "ipv4"),
        flags: ipv4Flags(value),
      });
    }
  }

  function extractIPv6(text, groups, seen) {
    var re = /[0-9A-Fa-f:]{2,}/g;
    var match;
    while ((match = re.exec(text))) {
      var raw = match[0];
      var value = raw;
      if (value.charAt(0) === ":" && value.indexOf("::") !== 0) value = value.slice(1);
      if (value.charAt(value.length - 1) === ":" && value.slice(-2) !== "::") {
        value = value.slice(0, -1);
      }
      if (!isValidIPv6(value)) continue;
      var after = text.charAt(match.index + raw.length);
      if (after === ".") continue;
      addUnique(groups.ipv6, seen.ipv6, {
        value: value,
        defanged: defangValue(value, "ipv6"),
        flags: ipv6Flags(value),
      });
    }
  }

  function extractDomains(text, groups, seen) {
    var re = /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+([a-z]{2,24})\b/gi;
    var match;
    while ((match = re.exec(text))) {
      var value = match[0].toLowerCase();
      if (!isAllowedTld(match[1])) continue;
      if (value.length > 253) continue;
      addUnique(groups.domains, seen.domains, {
        value: value,
        defanged: defangValue(value, "domain"),
        flags: [],
      });
    }
  }

  function extractUrls(text, groups, seen) {
    var re = /\b(?:https?|ftp):\/\/[^\s<>"']+/gi;
    var match;
    while ((match = re.exec(text))) {
      var value = trimUrl(match[0]);
      if (!value || !/^[a-z]+:\/\/[^\s/]+/i.test(value)) continue;
      addUnique(groups.urls, seen.urls, {
        value: value,
        defanged: defangValue(value, "url"),
        flags: [],
      }, value);
    }
  }

  function extractEmails(text, groups, seen) {
    var re = /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,24}\b/gi;
    var match;
    while ((match = re.exec(text))) {
      var value = match[0].toLowerCase();
      var tld = value.slice(value.lastIndexOf(".") + 1);
      if (!isAllowedTld(tld)) continue;
      addUnique(groups.emails, seen.emails, {
        value: value,
        defanged: defangValue(value, "email"),
        flags: [],
      });
    }
  }

  function extractHashes(text, groups, seen) {
    var re = /\b(?:[0-9a-fA-F]{64}|[0-9a-fA-F]{40}|[0-9a-fA-F]{32})\b/g;
    var match;
    while ((match = re.exec(text))) {
      var value = match[0].toLowerCase();
      var type = value.length === 64 ? "sha256" : value.length === 40 ? "sha1" : "md5";
      addUnique(groups[type], seen[type], {
        value: value,
        defanged: value,
        flags: [],
      });
    }
  }

  function extractCves(text, groups, seen) {
    var re = /\bCVE-\d{4}-\d{4,7}\b/gi;
    var match;
    while ((match = re.exec(text))) {
      var value = match[0].toUpperCase();
      addUnique(groups.cves, seen.cves, {
        value: value,
        defanged: value,
        flags: [],
      });
    }
  }

  function extractAttack(text, groups, seen) {
    var re = /\bT\d{4}(?:\.\d{3})?\b/gi;
    var match;
    while ((match = re.exec(text))) {
      var value = match[0].toUpperCase();
      addUnique(groups.attack, seen.attack, {
        value: value,
        defanged: value,
        flags: [],
      });
    }
  }

  function extract(input) {
    var text = refang(input);
    var groups = emptyGroups();
    var seen = {
      ipv4: new Set(),
      ipv6: new Set(),
      domains: new Set(),
      urls: new Set(),
      emails: new Set(),
      md5: new Set(),
      sha1: new Set(),
      sha256: new Set(),
      cves: new Set(),
      attack: new Set(),
    };

    extractUrls(text, groups, seen);
    extractEmails(text, groups, seen);
    extractDomains(text, groups, seen);
    extractIPv4(text, groups, seen);
    extractIPv6(text, groups, seen);
    extractHashes(text, groups, seen);
    extractCves(text, groups, seen);
    extractAttack(text, groups, seen);

    return groups;
  }

  function countAll(groups) {
    return TYPE_META.reduce(function (total, meta) {
      return total + groups[meta.key].length;
    }, 0);
  }

  function initUI() {
    if (typeof document === "undefined") return;

    var app = document.getElementById("ioc-app");
    if (!app || app.getAttribute("data-ioc-ready") === "1") return;
    app.setAttribute("data-ioc-ready", "1");

    var textarea = document.getElementById("ioc-input");
    var results = document.getElementById("ioc-results");
    var empty = document.getElementById("ioc-empty");
    var totalEl = document.getElementById("ioc-total");
    var statusEl = document.getElementById("ioc-status");
    var loadBtn = document.getElementById("load-sample");
    var clearBtn = document.getElementById("clear-input");
    var defangToggle = document.getElementById("defang-toggle");
    var exportJson = document.getElementById("export-json");
    var exportCsv = document.getElementById("export-csv");

    if (!textarea || !results) return;

    var groups = emptyGroups();
    var defangOutput = false;
    var timer = 0;

    function display(item) {
      return defangOutput ? item.defanged : item.value;
    }

    function flash(button, label) {
      if (!button) return;
      var original = button.getAttribute("data-label") || button.textContent;
      button.setAttribute("data-label", original);
      button.textContent = label;
      window.setTimeout(function () {
        button.textContent = original;
      }, 1200);
    }

    function fallbackCopy(text, done) {
      var ta = document.createElement("textarea");
      ta.value = text;
      ta.setAttribute("readonly", "");
      ta.style.position = "fixed";
      ta.style.top = "-1000px";
      ta.style.left = "-1000px";
      document.body.appendChild(ta);
      ta.select();
      try {
        if (document.execCommand("copy")) done();
      } catch (_) {
        /* Clipboard is best-effort. */
      }
      if (ta.parentNode) ta.parentNode.removeChild(ta);
    }

    function copyText(text, button) {
      if (!text) return;
      var done = function () {
        flash(button, "copied");
      };
      if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(text).then(done, function () {
          fallbackCopy(text, done);
        });
      } else {
        fallbackCopy(text, done);
      }
    }

    function render() {
      var total = countAll(groups);
      totalEl.textContent = total + " unique indicator" + (total === 1 ? "" : "s");
      statusEl.textContent = total
        ? "Parsed locally. Nothing was sent."
        : "Waiting for input.";
      empty.hidden = total > 0;
      if (exportJson) exportJson.disabled = total === 0;
      if (exportCsv) exportCsv.disabled = total === 0;

      results.textContent = "";

      TYPE_META.forEach(function (meta) {
        var items = groups[meta.key];
        if (!items.length) return;

        var section = document.createElement("section");
        section.className = "group";
        section.setAttribute("aria-labelledby", "group-" + meta.key);

        var head = document.createElement("div");
        head.className = "group__head";

        var title = document.createElement("h2");
        title.className = "group__title";
        title.id = "group-" + meta.key;
        title.textContent = meta.label;

        var count = document.createElement("span");
        count.className = "group__count";
        count.textContent = String(items.length);

        var copy = document.createElement("button");
        copy.type = "button";
        copy.className = "btn btn--small";
        copy.textContent = "copy";
        copy.setAttribute("aria-label", "Copy " + meta.label + " indicators");
        copy.addEventListener("click", function () {
          copyText(
            items
              .map(function (item) {
                return display(item);
              })
              .join("\n"),
            copy
          );
        });

        head.append(title, count, copy);

        var list = document.createElement("ul");
        list.className = "group__list";

        items.forEach(function (item) {
          var row = document.createElement("li");
          row.className = "indicator";

          var code = document.createElement("code");
          code.textContent = display(item);
          row.appendChild(code);

          if (item.flags && item.flags.length) {
            var flags = document.createElement("span");
            flags.className = "flags";
            item.flags.forEach(function (flag) {
              var badge = document.createElement("span");
              badge.className = "flag";
              badge.textContent = flag;
              flags.appendChild(badge);
            });
            row.appendChild(flags);
          }

          list.appendChild(row);
        });

        section.append(head, list);
        results.appendChild(section);
      });
    }

    function run() {
      window.clearTimeout(timer);
      timer = 0;
      groups = extract(textarea.value);
      render();
    }

    function schedule() {
      window.clearTimeout(timer);
      timer = window.setTimeout(run, 180);
    }

    function stamp() {
      var d = new Date();
      function pad(n) {
        return n < 10 ? "0" + n : String(n);
      }
      return (
        d.getFullYear() +
        pad(d.getMonth() + 1) +
        pad(d.getDate()) +
        "-" +
        pad(d.getHours()) +
        pad(d.getMinutes()) +
        pad(d.getSeconds())
      );
    }

    function download(filename, content, mime) {
      var blob = new Blob([content], { type: mime });
      var url = URL.createObjectURL(blob);
      var link = document.createElement("a");
      link.href = url;
      link.download = filename;
      document.body.appendChild(link);
      link.click();
      if (link.parentNode) link.parentNode.removeChild(link);
      window.setTimeout(function () {
        URL.revokeObjectURL(url);
      }, 1000);
    }

    function buildJson() {
      var indicators = [];
      TYPE_META.forEach(function (meta) {
        groups[meta.key].forEach(function (item) {
          indicators.push({
            type: meta.key,
            value: display(item),
            raw: item.value,
            flags: item.flags,
          });
        });
      });
      return JSON.stringify(
        {
          generatedAt: new Date().toISOString(),
          defanged: defangOutput,
          total: indicators.length,
          indicators: indicators,
        },
        null,
        2
      );
    }

    function csvCell(value) {
      var text = String(value == null ? "" : value);
      if (/[",\r\n]/.test(text)) {
        return '"' + text.replace(/"/g, '""') + '"';
      }
      return text;
    }

    function buildCsv() {
      var rows = [["type", "value", "flags"]];
      TYPE_META.forEach(function (meta) {
        groups[meta.key].forEach(function (item) {
          rows.push([meta.key, display(item), item.flags.join(";")]);
        });
      });
      return rows
        .map(function (row) {
          return row.map(csvCell).join(",");
        })
        .join("\r\n");
    }

    if (loadBtn) {
      loadBtn.addEventListener("click", function () {
        textarea.value = SAMPLE_TEXT;
        run();
        textarea.focus();
      });
    }

    if (clearBtn) {
      clearBtn.addEventListener("click", function () {
        textarea.value = "";
        run();
        textarea.focus();
      });
    }

    if (defangToggle) {
      defangToggle.addEventListener("change", function () {
        defangOutput = !!defangToggle.checked;
        render();
      });
    }

    if (exportJson) {
      exportJson.addEventListener("click", function () {
        download("iocs-" + stamp() + ".json", buildJson(), "application/json");
      });
    }

    if (exportCsv) {
      exportCsv.addEventListener("click", function () {
        download("iocs-" + stamp() + ".csv", buildCsv(), "text/csv");
      });
    }

    textarea.addEventListener("input", schedule);
    if (textarea.value.trim()) run();
    else render();
  }

  return {
    TYPE_META: TYPE_META,
    SAMPLE_TEXT: SAMPLE_TEXT,
    extract: extract,
    refang: refang,
    defang: defang,
    countAll: countAll,
    emptyGroups: emptyGroups,
    initUI: initUI,
  };
});

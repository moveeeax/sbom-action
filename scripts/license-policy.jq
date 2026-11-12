# license-policy.jq — evaluate a syft-json document against a license policy.
#
# Invoked by sbom_license_report (scripts/lib.sh) with:
#   --argjson allow        ["MIT", ...]     allowed SPDX ids/terms (empty = no allow list)
#   --argjson deny         ["AGPL-3.0-only"] denied SPDX ids/terms
#   --argjson exceptions   [{name, version, until, reason}] per-package waivers
#   --arg     today        YYYY-MM-DD; a waiver applies through its `until` date
#   --argjson allowUnknown true|false
#   --slurpfile spdx       scripts/spdx-licenses.json
#
# Semantics:
#   * SPDX ids and the AND/OR/WITH operators follow the SPDX expression syntax;
#     ids compare case-insensitively. AND binds tighter than OR. An expression
#     with nested parentheses is evaluated strictly: every id in it must pass.
#   * "X WITH exc" matches a list entry for the full term first, then for X,
#     so allowing "GPL-2.0-only WITH Classpath-exception-2.0" works while
#     "GPL-2.0-only" is denied. For the same term, deny wins over allow.
#   * A term is unknown when it is not a SPDX id after alias normalization
#     (LicenseRef-*, NOASSERTION, free text). A package with no license entries
#     is unknown too. Unknown fails unless allowUnknown, or unless the term is
#     named in the allow list.
#   * Several license entries on one package are all required to pass.
#   * A package with both declared and concluded entries whose id sets differ
#     is reported as a mismatch (e.g. package.json says MIT, LICENSE file is GPL).

# Common malformed spellings and deprecated ids -> SPDX id. Keys are lowercase.
def aliases: {
  "mit license": "MIT", "the mit license": "MIT", "mit-license": "MIT", "expat": "MIT",
  "apache 2.0": "Apache-2.0", "apache-2": "Apache-2.0", "apache 2": "Apache-2.0",
  "apache2": "Apache-2.0", "apache-2.0 license": "Apache-2.0", "asl 2.0": "Apache-2.0",
  "apache license 2.0": "Apache-2.0", "apache license, version 2.0": "Apache-2.0",
  "apache software license": "Apache-2.0", "apache software license 2.0": "Apache-2.0",
  "the apache software license, version 2.0": "Apache-2.0",
  "the apache license, version 2.0": "Apache-2.0",
  "bsd-3": "BSD-3-Clause", "bsd 3-clause": "BSD-3-Clause", "bsd-3-clause license": "BSD-3-Clause",
  "new bsd": "BSD-3-Clause", "new bsd license": "BSD-3-Clause", "modified bsd": "BSD-3-Clause",
  "bsd 3-clause license": "BSD-3-Clause",
  "bsd-2": "BSD-2-Clause", "bsd 2-clause": "BSD-2-Clause", "simplified bsd": "BSD-2-Clause",
  "bsd 2-clause license": "BSD-2-Clause",
  "isc license": "ISC",
  "mpl 2.0": "MPL-2.0", "mpl-2": "MPL-2.0", "mozilla public license 2.0": "MPL-2.0",
  "the unlicense": "Unlicense", "cc0": "CC0-1.0", "cc0 1.0": "CC0-1.0",
  "gplv2": "GPL-2.0-only", "gpl-2": "GPL-2.0-only", "gpl v2": "GPL-2.0-only",
  "gpl-2.0": "GPL-2.0-only", "gpl-2.0+": "GPL-2.0-or-later", "gplv2+": "GPL-2.0-or-later",
  "gplv3": "GPL-3.0-only", "gpl-3": "GPL-3.0-only", "gpl v3": "GPL-3.0-only",
  "gpl-3.0": "GPL-3.0-only", "gpl-3.0+": "GPL-3.0-or-later", "gplv3+": "GPL-3.0-or-later",
  "gpl-1.0": "GPL-1.0-only", "gpl-1.0+": "GPL-1.0-or-later",
  "lgplv2.1": "LGPL-2.1-only", "lgpl-2.1": "LGPL-2.1-only", "lgpl-2.1+": "LGPL-2.1-or-later",
  "lgplv3": "LGPL-3.0-only", "lgpl-3.0": "LGPL-3.0-only", "lgpl-3.0+": "LGPL-3.0-or-later",
  "lgpl-2.0": "LGPL-2.0-only", "lgpl-2.0+": "LGPL-2.0-or-later",
  "agplv3": "AGPL-3.0-only", "agpl-3.0": "AGPL-3.0-only", "agpl-1.0": "AGPL-1.0-only",
  "gfdl-1.1": "GFDL-1.1-only", "gfdl-1.2": "GFDL-1.2-only", "gfdl-1.3": "GFDL-1.3-only"
};

($spdx[0].ids | map({key: ascii_downcase, value: .}) | from_entries) as $ids |

# Normalize one id (no operators) to its SPDX spelling; unknown ids pass through.
def norm_id: (ascii_downcase | gsub("^\\s+|\\s+$"; "")) as $k
    | aliases[$k] // $ids[$k] // (. | gsub("^\\s+|\\s+$"; ""));

# Normalize a term that may carry "WITH exception".
def norm_term:
    if test(" WITH ") then
      (split(" WITH ") | (.[0] | norm_id) + " WITH " + (.[1:] | join(" WITH ") | gsub("^\\s+|\\s+$"; "")))
    else norm_id end;

def base_id: split(" WITH ")[0];

# List entries go through the same normalization, so "Apache 2.0" or the
# deprecated "GPL-3.0" in the policy match what Syft reports.
($allow | map(norm_term | ascii_downcase)) as $allowL
| ($deny | map(norm_term | ascii_downcase)) as $denyL
| def is_spdx: $ids[base_id | ascii_downcase] != null;

# allowed | denied | not-allowed | unknown
def term_status:
    (ascii_downcase) as $t | (base_id | ascii_downcase) as $b
    | if ($denyL | index($t)) then "denied"
      elif ($allowL | index($t)) then "allowed"
      elif ($denyL | index($b)) then "denied"
      elif ($allowL | index($b)) then "allowed"
      elif (is_spdx | not) then "unknown"
      elif ($allowL | length) > 0 then "not-allowed"
      else "allowed" end;

def term_pass: . as $s | ($s == "allowed") or ($s == "unknown" and $allowUnknown);

# Expression string -> [[term]] (OR of ANDs). One pair of parentheses around
# the whole expression is dropped; any other parentheses -> one AND group.
def clauses:
    (if test("^\\s*\\([^()]*\\)\\s*$") then gsub("^\\s*\\(|\\)\\s*$"; "") else . end)
    | if test("[()]") then
      [gsub("[()]"; " ") | gsub(" OR "; " AND ") | split(" AND ")
        | map(gsub("^\\s+|\\s+$"; "")) | map(select(. != "")) | map(norm_term)]
    else
      split(" OR ") | map(split(" AND ") | map(gsub("^\\s+|\\s+$"; "")) | map(select(. != "")) | map(norm_term))
    end;

# Evaluate one syft license entry.
def eval_license:
    ((.spdxExpression // "") | if . == "" then null else . end) as $expr
    | ($expr // (.value // "")) as $raw
    | ($raw | clauses | map(select(length > 0))) as $cl
    | ($cl | map(map({term: ., status: term_status}))) as $evald
    | {
        value: (.value // ""),
        expression: ($cl | map(join(" AND ")) | join(" OR ")),
        type: (.type // ""),
        location: ((.locations // [])[0].path // ""),
        terms: ($evald | add // [] | unique_by(.term)),
        pass: (($evald | length) > 0 and ($evald | any(all(.status | term_pass))))
      };

def exception_for($name; $version):
    [$exceptions[] | select(.name == $name and ((.version // "") == "" or .version == $version))] | first;

[.artifacts[]? | . as $a
    | ((.licenses // []) | map(eval_license)) as $lic
    | ($lic | map(select(.type == "declared") | .terms[].term | ascii_downcase) | unique) as $decl
    | ($lic | map(select(.type == "concluded") | .terms[].term | ascii_downcase) | unique) as $conc
    | (($decl | length) > 0 and ($conc | length) > 0 and $decl != $conc) as $mismatch
    | (if ($lic | length) == 0 then $allowUnknown else ($lic | all(.pass)) end) as $pass
    | exception_for($a.name; $a.version // "") as $exc
    | (if $exc == null then null elif $exc.until >= $today then "active" else "expired" end) as $excState
    | {
        name: $a.name,
        version: ($a.version // ""),
        type: ($a.type // ""),
        licenses: $lic,
        mismatch: $mismatch,
        exception: (if $exc == null then null else ($exc + {state: $excState}) end),
        status: (if $pass then "ok"
                 elif $excState == "active" then "excepted"
                 elif ($lic | length) == 0 then "unknown"
                 else "violation" end)
      }
  ] as $pkgs
| {
    packages: $pkgs,
    violations: ($pkgs | map(select(.status == "violation" or .status == "unknown")) | length),
    mismatches: ($pkgs | map(select(.mismatch)) | length),
    expiredExceptions: ($pkgs | map(select(.exception.state == "expired") | .exception) | unique),
    unusedExceptions: ($exceptions | map(. as $e
      | select(($pkgs | any(.name == $e.name and (($e.version // "") == "" or .version == $e.version))) | not)))
  }

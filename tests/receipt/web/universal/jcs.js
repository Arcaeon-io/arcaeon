/* universal/jcs.js: RFC 8785 JSON Canonicalization Scheme.
 *
 * This is NOT Arcaeon's json-c14n v1 (that one lives, pinned, in
 * verify-receipt.html between C14N-START and C14N-END, and is loaded here only
 * through the derived universal/c14n_pinned.js). JCS is a different recipe:
 * keys sort by UTF-16 code units, numbers are IEEE doubles printed the way
 * ECMAScript prints them, strings are escaped the way JSON.stringify escapes
 * them. Spec read: https://www.rfc-editor.org/rfc/rfc8785.html (sections 3.1,
 * 3.2.2, 3.2.3). Formats that sign over JCS: Agent Receipts (spec v0.5.0 s7.1).
 *
 * Input is a value from JSON.parse over text that has already passed the
 * duplicate-key scan (I-JSON forbids duplicates, RFC 8785 s3.1).
 */
"use strict";

function JCSError(message) { this.name = "JCSError"; this.message = message; }
JCSError.prototype = Object.create(Error.prototype);

UC.jcs = function (value) {
  if (value === null) { return "null"; }
  if (value === true) { return "true"; }
  if (value === false) { return "false"; }
  if (typeof value === "number") {
    if (!isFinite(value)) { throw new JCSError("a number that is not finite cannot be canonicalized"); }
    return String(value); // ECMAScript Number-to-String, which RFC 8785 s3.2.2.3 adopts
  }
  if (typeof value === "string") {
    if (/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?:[^\uD800-\uDBFF]|^)[\uDC00-\uDFFF]/.test(value)) {
      throw new JCSError("a string holds a lone surrogate, which I-JSON forbids");
    }
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) { return "[" + value.map(UC.jcs).join(",") + "]"; }
  if (typeof value === "object") {
    var keys = Object.keys(value).sort(function (a, b) { return a < b ? -1 : (a > b ? 1 : 0); });
    return "{" + keys.map(function (k) { return UC.jcs(k) + ":" + UC.jcs(value[k]); }).join(",") + "}";
  }
  throw new JCSError("unsupported JSON value");
};

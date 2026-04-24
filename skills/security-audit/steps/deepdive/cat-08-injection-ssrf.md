# Deep Dive #8 — Injection / SSRF / Deserialization

**Category.** `injection`.

**OWASP tags.**
- ASVS: V5 (Validation, Sanitization, Encoding), V12.3 (File Resources).
- API Top 10: `API8:2023`, `API10:2023`.

**Baseline CWEs:** 20, 22, 77, 78, 79, 89, 91, 94, 434, 502, 601, 611, 776,
918, 943.

---

## Invariants

1. No SQL built by string concatenation of user input.
2. No NoSQL operators (`$where`, `$regex` with user input) accepted.
3. No OS commands invoked with `shell: true` + user-controlled string.
4. XML parsers harden against XXE (no external entities, no DTDs).
5. Template engines don't render user-controlled templates (SSTI).
6. SSRF defenses in place when HTTP client consumes a user-supplied URL
   (IP allowlist, block IMDS, block loopback / private networks).
7. Unsafe deserializers are not called on untrusted input.
8. File uploads validate extension / MIME type / magic bytes AND strip
   EXIF / dangerous metadata.
9. Redirect `Location` headers target allowlisted hosts.

## Detection patterns

### SQL injection

Most scanner hits already land on this. Augment with handler-body greps:

```
# JS/TS (Sequelize/Knex/TypeORM)
query\s*\(\s*`SELECT[\s\S]*?\$\{[^}]+\}
raw\s*\(\s*`[^`]*\$\{
sequelize\.query\s*\(\s*["`'].*\+

# Python (psycopg/SQLAlchemy)
cursor\.execute\s*\(\s*f["']
cursor\.execute\s*\(\s*['"][^'"]*['"]\s*\+
db\.session\.execute\s*\(\s*f["']

# Go
db\.Exec\s*\(\s*fmt\.Sprintf\s*\(

# Java/Kotlin
createStatement\(\)\.executeQuery\s*\(\s*".*"\s*\+
jdbcTemplate\.queryForList\s*\(\s*".*"\s*\+

# PHP
mysqli_query\s*\([^)]*\$_(GET|POST|REQUEST)

# Ruby
where\s*\(\s*"[^"]*#\{[^}]+\}"
ActiveRecord::Base\.connection\.execute\s*\(.*#\{
```

→ **CRITICAL** / CWE-89.

### NoSQL injection

```
# Mongo / Mongoose
find\s*\(\s*\{\s*[^}]*:\s*req\.(body|query|params)\.[^}]+\}
find\s*\(\s*req\.body\s*\)
\$where\s*:\s*['"][^'"]*\$\{
\$regex\s*:\s*req\.
```

→ **HIGH** / CWE-943.

### Command injection

```
# Node
child_process\.(exec|execSync)\s*\(
spawn\s*\([^,]+,\s*[^,]+,\s*\{[^}]*shell\s*:\s*true
execSync\s*\(

# Python
os\.system\s*\(
subprocess\.(run|call|Popen)\s*\([^,]+,\s*shell\s*=\s*True
os\.popen\s*\(

# Go
exec\.Command\s*\(\s*"(sh|bash)"

# PHP
shell_exec|passthru|system|exec\b
backtick string ``...``

# Ruby
`#\{...\}`
system\s*\(.*#\{
Open3\.popen.*shell
```

Check if argument references user input directly → **CRITICAL** /
CWE-77 / CWE-78.

### XXE

```
# Python
etree\.parse\s*\(                    # lxml default is safe post-4.x; verify version
xml\.sax\.make_parser\(\)            # without setFeature for external entities
xml\.dom\.minidom\.parse\s*\(

# Java
DocumentBuilderFactory\.newInstance\(\)   # without setFeature for XXE
SAXParserFactory\.newInstance\(\)          # same

# .NET
new XmlTextReader\s*\(                   # pre-.NET 4.5.2 defaults unsafe
```

Any instance without explicit `setFeature(".../load-external-dtd", false)`
→ **HIGH** / CWE-611.

### SSTI

```
# Jinja2
render_template_string\s*\(\s*(?!['"])
Template\s*\(\s*user_input

# Ruby ERB
ERB\.new\s*\(\s*params\b

# Go html/template
template\.HTML\s*\(\s*userInput
```

User input into template constructor → **CRITICAL** / CWE-94.

### SSRF

For every `outbound_tls` surface in Phase 2 where the URL derives from
user input (`fetch(req.body.url)`, `requests.get(request.args["url"])`),
check for:
- IP allowlist / host allowlist enforcement
- Block for loopback (127.0.0.0/8), link-local (169.254.0.0/16), private
  (RFC1918), IMDS (169.254.169.254), DNS rebinding protection.

Absence → **HIGH** / CWE-918.

### Unsafe deserialization

```
# Python
pickle\.loads?\s*\(
cPickle\.loads?\s*\(
yaml\.load\s*\(            # not yaml.safe_load

# JS/TS
JSON\.parse\s*\(\s*.*\)\s*;  # safe by itself; flag only when reviver is a function
node-serialize|serialize-javascript\.unserialize

# Java
ObjectInputStream\s*\([^)]+\)\.readObject\(\)
Marshaller\.unmarshal\b   # JAXB — verify hardened

# .NET
BinaryFormatter\.Deserialize
SoapFormatter\.Deserialize
NetDataContractSerializer

# PHP
unserialize\s*\(          # without allowed_classes

# Ruby
Marshal\.load\s*\(
YAML\.load\s*\(           # not YAML.safe_load
```

All of these on user-controlled data → **CRITICAL** / CWE-502.

### File upload

For each `file_upload` surface in Phase 2:
- Check MIME / extension / magic-bytes validation.
- Check destination path is not constructed from user input (path
  traversal / CWE-22).
- Check image files are re-encoded (strip malicious EXIF / polyglot).
- Check upload size limits.

Missing any → **HIGH** / CWE-434 or **HIGH** / CWE-22.

### Open redirect

```
res\.redirect\s*\(\s*req\.(body|query|params)\.
return\s+redirect\s*\(\s*request\.args\.get\s*\(
HttpResponseRedirect\s*\(\s*request\.(GET|POST)\.
```

→ **MEDIUM** / CWE-601.

## Cross-reference with scanners

Most of these already land in semgrep `p/owasp-top-ten` + bandit + psalm.
For each grep match that also appears in a scanner's slim-SARIF, set
`confidence: CONFIRMED`.

## Output

`phase-05-injection-<partition>.jsonl`.

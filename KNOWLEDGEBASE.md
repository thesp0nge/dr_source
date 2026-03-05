# DRSource Security Knowledge Base

This document outlines the security vulnerabilities detected by DRSource, the detection methods used (AST Taint Analysis vs. Regex), and the language-specific coverage.

## Vulnerability Categories

### 1. Injections (RCE & Data Breach)
| Category | Languages | Method | Coverage |
| :--- | :--- | :--- | :--- |
| **SQL Injection** | Java, Python, JS, PHP, Ruby | AST | Full support for PreparedStatements, SQLAlchemy, Django ORM, ActiveRecord, and mysqli. Supports call chaining and field-sensitivity. |
| **Command Injection** | Java, Python, JS, PHP, Ruby | AST | Detects unsanitized input reaching `os.system`, `subprocess`, `child_process.exec`, `system()`, and backticks. |
| **NoSQL Injection** | Python, JS | AST | Coverage for MongoDB (`collection.find`) and Mongoose. |
| **XXE Injection** | Java, Python | AST+Regex | Detects insecure XML parser configurations (e.g., `resolve_entities=True` in lxml). |

### 2. Modern Web & Framework Risks
| Category | Languages | Method | Coverage |
| :--- | :--- | :--- | :--- |
| **Mass Assignment** | Python, Ruby, PHP | Structural | Detects insecure model binding like Django `fields = '__all__'` and Rails direct `params` passing to `create/update`. |
| **SSTI** | Python, JS, Java, Ruby | AST | Coverage for Jinja2, Mako, EJS, Pug, Handlebars, and ERB. |
| **SSRF** | All Core | AST | Extensive mapping for modern HTTP clients: `requests`, `httpx`, `aiohttp`, `axios`, `got`, `node-fetch`, `OkHttpClient`. |
| **Insecure JWT** | Python, JS, Java | AST+Regex | Detects `verify=False` and algorithms allowing `none` type bypass. |

### 3. Execution & Logic Flaws
| Category | Languages | Method | Coverage |
| :--- | :--- | :--- | :--- |
| **Deserialization** | Python, Java, PHP, Ruby | AST | Detects untrusted data in `pickle`, `Marshal`, `unserialize`, and Java `ObjectInputStream`. |
| **Insecure Reflection** | Java, Python, Ruby | AST | Detects user-controlled class loading or method invocation (`getattr`, `Class.forName`). |
| **Unsafe File Include**| PHP | AST | Detects LFI/RFI via `include`, `require`, and their variants. |
| **Insecure Token Gen** | Python, Java, JS | AST | Detects sensitive tokens (passwords, sessions) generated with `random.random()` or `Math.random()`. |

### 4. Compliance & Data Safety
| Category | Languages | Method | Coverage |
| :--- | :--- | :--- | :--- |
| **Weak Crypto** | Python, Java, JS | AST+Regex | Detects MD5, SHA1, DES, and AES-ECB usage. |
| **PII Leakage** | All Core | Heuristic | Automatically marks variables named `email`, `password`, `cc`, etc., as sources and tracks them to output sinks. |
| **Hardcoded Secrets** | All | Regex | High-entropy detection for AWS keys, SSH keys, and generic assignments like `api_key = "..."`. |
| **Log Injection** | All Core | AST | Detects unsanitized input reaching application logs (`logging.info`, `console.log`). |

## Detection Depth Highlights

### Field-Sensitive Analysis
DRSource tracks data at the property level. It can distinguish between `user.name` (tainted) and `user.id` (safe), reducing noise in object-oriented codebases.

### Framework Intelligence
The engine understands framework-specific entry points:
- **Spring Boot**: `@RequestParam`, `@PathVariable`.
- **FastAPI**: Function parameters in route decorators.
- **Django**: The `request` object and `ModelForm` configurations.
- **Node.js**: `req.query`, `req.body`.

### Constant Propagation
A built-in engine tracks literal values and string concatenations to automatically ignore safe sinks, ensuring that only real data-flow threats are reported.

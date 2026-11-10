# Security benchmark: qwen2.5-coder-14b-q5km

Scored 2026-11-09T17:00:04 - 32/32 tasks, 0 errors, 0 invalid JSON, 38.0 min model time, prompt version(s) [1]

**Overall full-credit: 37.5%**

## Track A: code audit

| verdict acc | precision | recall | false alarms on fixed twins | CWE acc | line acc | full credit |
|---|---|---|---|---|---|---|
| 50.0% | 50.0% | 100.0% | 100.0% | 58.3% | 58.3% | 29.2% |

## Track B: log forensics

| attacker IP | technique | first seen | account | all four |
|---|---|---|---|---|
| 100.0% | 62.5% | 75.0% | 100.0% | 62.5% |

## Per task

| task | key | answer | result | prompt tok | time s |
|---|---|---|---|---|---|
| code-c05-vuln | integer overflow in allocation size L[33] | vuln=True CWE-190 L33 | ✅ | 693 | 19 |
| code-js01-vuln | IDOR / missing ownership check L[20] | vuln=True CWE-89 L31 | ◐ cwe,line,full | 649 | 21 |
| code-py02-vuln | OS command injection via shell=True L[27, 28] | vuln=True CWE-78 L27 | ✅ | 555 | 19 |
| code-py04-vuln | insecure deserialization (pickle from cookie) L[15] | vuln=True CWE-502 L15 | ✅ | 556 | 16 |
| code-c02-vuln | off-by-one NUL write L[17, 22] | vuln=True CWE-190 L38 | ◐ cwe,line,full | 600 | 18 |
| code-py03-vuln | path traversal L[20, 22] | vuln=True CWE-73 L20 | ✅ | 536 | 17 |
| code-c04-vuln | use after free in error path L[41] | vuln=True CWE-457 L13 | ◐ cwe,line,full | 789 | 23 |
| code-js01-fixed | safe | vuln=True CWE-89 L20 | ◐ verdict,full | 659 | 17 |
| code-c06-vuln | TOCTOU access()/open() in setuid program L[26, 31] | vuln=True CWE-78 L37 | ◐ cwe,line,full | 701 | 19 |
| code-py01-vuln | SQL injection L[31] | vuln=True CWE-89 L31 | ✅ | 613 | 17 |
| code-c02-fixed | safe | vuln=True CWE-121 L17 | ◐ verdict,full | 603 | 15 |
| code-php01-vuln | unsalted MD5 password hashing L[11, 24] | vuln=True CWE-327 L11 | ✅ | 607 | 18 |
| code-c04-fixed | safe | vuln=True CWE-457 L13 | ◐ verdict,full | 789 | 20 |
| code-py03-fixed | safe | vuln=True CWE-73 L15 | ◐ verdict,full | 572 | 16 |
| code-c01-vuln | stack/struct buffer overflow via strcpy L[31] | vuln=True CWE-120 L31 | ✅ | 684 | 22 |
| code-php01-fixed | safe | vuln=True CWE-78 L31 | ◐ verdict,full | 608 | 18 |
| code-c06-fixed | safe | vuln=True CWE-78 L30 | ◐ verdict,full | 742 | 16 |
| code-py01-fixed | safe | vuln=True CWE-89 L30 | ◐ verdict,full | 612 | 16 |
| code-c03-vuln | format string L[14] | vuln=True CWE-120 L28 | ◐ cwe,line,full | 603 | 18 |
| code-py04-fixed | safe | vuln=True CWE-798 L15 | ◐ verdict,full | 557 | 18 |
| code-c05-fixed | safe | vuln=True CWE-190 L37 | ◐ verdict,full | 745 | 17 |
| code-py02-fixed | safe | vuln=True CWE-78 L27 | ◐ verdict,full | 551 | 14 |
| code-c01-fixed | safe | vuln=True CWE-789 L32 | ◐ verdict,full | 692 | 17 |
| code-c03-fixed | safe | vuln=True CWE-120 L28 | ◐ verdict,full | 603 | 17 |
| log-L1 | 109.56.148.159 brute_force 11:33:49 backup | 109.56.148.159 brute_force Nov  3 11:33:49 web01 sshd[28529]: Failed password for backup from 109.56.148.159 port 52181 ssh2 backup | ✅ | 7064 | 122 |
| log-L2 | 193.213.110.8 sqli 09:51:25 none | 193.213.110.8 sqli 193.213.110.8 - - [03/Nov/2026:09:51:25 +0000] "GET /products.php?id=12 HTTP/1.1" 200 31867 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0" none | ✅ | 5572 | 103 |
| log-L3 | 77.197.77.167 path_traversal 16:35:15 none | 77.197.77.167 path_traversal 77.197.77.167 - - [03/Nov/2026:16:35:15 +0000] "GET /download?file=manual-7.pdf HTTP/1.1" 200 2523 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0" none | ✅ | 7419 | 141 |
| log-L4 | 159.194.3.25 password_spray 10:27:52 jsmith | 159.194.3.25 brute_force Nov  3 10:12:40 web01 sshd[16158]: Failed password for invalid user jenkins from 159.194.3.25 port 45331 ssh2 jsmith | ◐ technique,first_seen,full | 9008 | 158 |
| log-L5 | 109.64.29.121 web_shell 12:20:43 none/www-data | 109.64.29.121 web_shell 109.64.29.121 - - [03/Nov/2026:12:20:43 +0000] "POST /upload.php HTTP/1.1" 200 87 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0" none | ✅ | 11322 | 210 |
| log-L6 | 23.75.191.149 cron_persistence 14:27:06 svc-git | 23.75.191.149 brute_force Nov  3 14:27:06 web01 sshd[1411]: Accepted password for svc-git from 23.75.191.149 port 48296 ssh2 svc-git | ◐ technique,full | 14601 | 296 |
| log-L7 | 141.79.72.158 ssh_key_persistence 16:28:48 dbadmin/root | 141.79.72.158 brute_force Nov  3 16:28:48 web01 sshd[8182]: Failed password for invalid user pi from 103.254.124.130 port 57997 ssh2 dbadmin | ◐ technique,first_seen,full | 16848 | 330 |
| log-L8 | 103.77.49.90 brute_force 10:59:17 none | 103.77.49.90 brute_force Nov  3 10:59:17 web01 sshd[57733]: Failed password for admin from 103.77.49.90 port 50056 ssh2 none | ✅ | 22287 | 492 |

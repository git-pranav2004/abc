Full Detailed Report — WAF Lab (VMware / Ubuntu / DVWA / ModSecurity / CRS / Custom Rules)

Scope / purpose

This document is a full, in-depth record of everything we did in the lab up to now — from the VM basics to installing DVWA, installing and configuring ModSecurity + OWASP CRS, creating and testing custom rules, debugging, and logging. It contains exact commands, full config snippets, test examples, and troubleshooting steps so you or any teammate can reproduce, audit, or present the lab end-to-end.

Save this as WAF_Lab_Full_Documentation.md in your project repo. Read the “Quick navigation” if you want specific sections fast.

Quick navigation

Prerequisites & environment

VM / networking basics

Ubuntu initial setup commands

Install & configure Apache, PHP, MariaDB

Install DVWA (deploy web application)

Install ModSecurity & OWASP CRS

Key ModSecurity configuration files (full samples)

Custom local rules (the ones we used)

Testing workflow (DVWA UI + curl) with exact commands

Logs and parsing (audit log structure + grep examples)

Common errors we encountered & fixes (with commands)

Safe rules lifecycle and best practices

Backups, snapshots, and safe demo checklist

Appendix: Useful scripts & snippets you can copy-paste

Prerequisites & environment

Host: your workstation with VMware Workstation / Player.

Guest: Ubuntu (tested on Ubuntu 22.04 / 24.04 family — commands are Debian/Ubuntu-compatible).

Network mode: Bridged or Host-Only with proper routing between host and VM; in our lab we used a host-accessible VM IP (e.g., 192.168.250.130).

Access: user with sudo privileges inside the Ubuntu VM.

Tools used: apache2, php, mariadb (or mysql), git, libapache2-mod-security2 (ModSecurity), enscript/ps2pdf (optional PDF export).

Application to protect: DVWA installed in /var/www/html/dvwa.

VM & networking basics (short)

Boot VM in VMware.

Verify IP inside VM:

hostname -I
# Example output: 192.168.250.130


From host, confirm HTTP reachability:

# from host machine
```curl -I http://<VM_IP>/```


If host cannot reach the VM, check VMware network adapter (Bridged vs NAT vs Host-Only) and host firewall.

Ubuntu initial setup (commands to run once after boot)

Run these inside the VM terminal:

# update packages list
```sudo apt update```

# upgrade (optional)
```sudo apt upgrade -y```

# install base tools we will use
```sudo apt install -y git curl wget unzip nano less build-essential```

Install & configure Apache, PHP, MariaDB (full commands)

These commands set up the web stack used by DVWA.

# Install Apache, PHP, PHP extensions, MariaDB
```sudo apt install -y apache2 php php-mysqli php-xml php-mbstring php-curl libapache2-mod-php mariadb-server```

# Start & enable services
```sudo systemctl enable --now apache2```
```sudo systemctl enable --now mariadb```

# Secure MariaDB (interactive)
```sudo mysql_secure_installation```
# follow prompts (set root password if needed, remove anonymous users, disallow root remote login, remove test DB, reload privilege tables)


If MariaDB root is using unix_socket for auth (Ubuntu default), you can set DVWA db user like this:

# login as root using socket
```sudo mysql -u root```

# inside mysql
CREATE DATABASE dvwa;
CREATE USER 'dvwa'@'localhost' IDENTIFIED BY 'dvwa_password';
GRANT ALL PRIVILEGES ON dvwa.* TO 'dvwa'@'localhost';
FLUSH PRIVILEGES;
EXIT;


(Change dvwa_password accordingly and note these credentials for DVWA setup.)

Install DVWA (full step-by-step)

Download DVWA:

cd /var/www/html
```sudo git clone https://github.com/digininja/DVWA.git dvwa```

Set permissions:

```sudo chown -R www-data:www-data /var/www/html/dvwa```
```sudo chmod -R 755 /var/www/html/dvwa```


Configure DVWA: copy config template and edit:

```sudo cp /var/www/html/dvwa/config/config.inc.php.dist /var/www/html/dvwa/config/config.inc.php```
```sudo nano /var/www/html/dvwa/config/config.inc.php```


Inside config.inc.php set DB credentials (example lines to modify):

```$_DVWA[ 'db_user' ] = 'dvwa';```
```$_DVWA[ 'db_password' ] = 'dvwa_password';```
```$_DVWA[ 'db_database' ] = 'dvwa';```


Import DB / run setup:

Option A (web): Open http://<VM_IP>/dvwa/setup.php and click Create / Reset Database.

Option B (manual with SQL dump if necessary).

Open DVWA in host browser:

```http://<VM_IP>/dvwa/```


Default login: admin / password (change in DVWA settings if needed).

Set security level to Low for initial testing.

Install ModSecurity + OWASP CRS

We installed ModSecurity (Apache module) and fetched CRS. Commands below assume apt packages and manual copying of CRS rules into /etc/modsecurity/crs.

Install ModSecurity (Debian/Ubuntu package):

```sudo apt install -y libapache2-mod-security2```


Check module loaded:

```sudo apachectl -M | grep security2```
# expected: security2_module (shared)


Create ModSecurity directory & ensure main config exists:

On Debian the package installs /etc/modsecurity/modsecurity.conf. If not, copy the recommended starter:

# If installed package placed modsecurity.conf-recommended:
```sudo cp /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf```


Install OWASP CRS (copy rules into /etc/modsecurity/crs):

# install git if not present
```sudo apt install -y git```

# clone CRS to temporary folder
```sudo git clone https://github.com/coreruleset/coreruleset.git /tmp/owasp-crs```

# create crs folder and copy files
```sudo mkdir -p /etc/modsecurity/crs```
```sudo cp /tmp/owasp-crs/crs-setup.conf.example /etc/modsecurity/crs/crs-setup.conf```
```sudo cp -r /tmp/owasp-crs/rules /etc/modsecurity/crs/```


Edit Apache modsecurity loader (/etc/apache2/mods-enabled/security2.conf) so it includes the main config and CRS (single include set). Replace content with the snippet below (be careful to not include duplicate includes):

```<IfModule security2_module>
    SecDataDir /var/cache/modsecurity

    # Load main config
    IncludeOptional /etc/modsecurity/modsecurity.conf

    # Load CRS setup and rules
    IncludeOptional /etc/modsecurity/crs/crs-setup.conf
    IncludeOptional /etc/modsecurity/crs/rules/*.conf
</IfModule>```


Important: Do not include /etc/modsecurity/*.conf and the explicit paths at the same time — duplicate includes cause duplicate rule IDs and Apache will fail to start.

Restart Apache and verify CRS loaded:

```sudo apachectl configtest```
```sudo systemctl restart apache2```
```sudo tail -n 50 /var/log/apache2/error.log```


Look for messages like ModSecurity: Loaded ... rules or similar.

Key ModSecurity configuration files — full samples & explanation

Below are the key files and the snippets we used/modified. Always back up original files before editing.

/etc/apache2/mods-enabled/security2.conf (what it should contain)
<IfModule security2_module>
    SecDataDir /var/cache/modsecurity

    # Load the main ModSecurity configuration
    IncludeOptional /etc/modsecurity/modsecurity.conf

    # Load OWASP CRS
    IncludeOptional /etc/modsecurity/crs/crs-setup.conf
    IncludeOptional /etc/modsecurity/crs/rules/*.conf

    # Optionally include local rules
    IncludeOptional /etc/modsecurity/local/*.conf
</IfModule>


Note: we include /etc/modsecurity/local/*.conf to read our custom local rules.

/etc/modsecurity/modsecurity.conf (key settings to verify)

Be sure the file contains or is set to:

# Turn ModSecurity on (or use DetectionOnly while tuning)
SecRuleEngine On
# or
# SecRuleEngine DetectionOnly

# Where to write audit log
SecAuditLog /var/log/apache2/modsec_audit.log

# Persistence directory
SecDataDir /var/cache/modsecurity


Also check SecAuditLogParts and other audit settings; default is OK for lab.

/etc/modsecurity/crs/crs-setup.conf

(we copied example from core rules repo; do not duplicate its contents here — keep the file copied as crs-setup.conf)

Important: local include

We manage our custom rules under:

/etc/modsecurity/local/local_rules.conf


(We included /etc/modsecurity/local/*.conf in security2.conf.)

Custom local rules — exact file content we used

Path: /etc/modsecurity/local/local_rules.conf
(We recommend storing all custom rules in a single file or one file per rule to ease management.)

File content (the three rules we used in the lab):

# /etc/modsecurity/local/local_rules.conf
# Custom local rules - IDs in 100001..100999

# Rule 1 - Simple XSS detector (blocks)
SecRule ARGS "@rx (?i)<script" \
  "id:100001,phase:2,deny,log,msg:'Custom_XSS_Attempt_Blocked',severity:2"

# Rule 2 - Simple SQLi detector (log-only)
SecRule ARGS "@rx (?i)(\bUNION\b|\bSELECT\b.*\bFROM\b|\bOR\s+1=1\b|'\-\-)" \
  "id:100002,phase:2,pass,log,msg:'Custom_SQLi_Detected',severity:2"

# Rule 3 - Block risky file-upload extensions (deny)
SecRule REQUEST_HEADERS:Content-Disposition "@rx (?i)filename=.*\.(php|phtml|jsp|asp|aspx|exe|sh|pl|cgi)\b" \
  "id:100003,phase:2,deny,status:403,log,msg:'Custom_Blocked_Upload_Ext',severity:3"


Notes:

Use unique IDs (≥100000) and never reuse CRS IDs.

Start with pass,log during tuning (we used pass for SQLi initially).

deny will return 403/interrupt the request.

Permissions:

```sudo chown root:root /etc/modsecurity/local/local_rules.conf```
```sudo chmod 644 /etc/modsecurity/local/local_rules.conf```

Testing workflow — step-by-step (DVWA UI + curl)

Important: always configtest after edits:

```sudo apachectl configtest```
# expect: Syntax OK
```sudo systemctl reload apache2```

1) Start live log watcher (open in VM)

Use multi-line audit log (preferred):

```sudo tail -f /var/log/apache2/modsec_audit.log```
# If audit log empty, use:
```sudo tail -f /var/log/apache2/error.log```

2) XSS (Reflected) test — DVWA UI

In host browser: http://<VM_IP>/dvwa/ → login → Vulnerabilities → XSS (Reflected)

Message field:

<script>alert('XSS')</script>


Click Sign Guestbook.

Expected: 403 Forbidden if rule 100001 is deny. In the VM tail you should see an audit block including:

id "100001"
msg "Custom_XSS_Attempt_Blocked"

3) SQLi test — DVWA UI (log-only for 100002)

DVWA → Vulnerabilities → SQL Injection → insert:

1' OR '1'='1


Submit.

Expected: page may still respond (because rule is pass), but audit log or error log will record id "100002" and Custom_SQLi_Detected.

curl alternative (GET):

curl -i "http://<VM_IP>/dvwa/vulnerabilities/sqli/?id=1'%20OR%20'1'='1"

4) File upload test — DVWA or simulated multipart curl

If DVWA has an upload page (path /dvwa/vulnerabilities/upload/), use it to upload a file named test.php. Or simulate multipart:

curl -i -X POST -F "uploaded=@/etc/hosts;filename=test.php" "http://<VM_IP>/dvwa/vulnerabilities/upload/"


Expected: 403 and audit log entry with id "100003" and message Custom_Blocked_Upload_Ext.

Logs and parsing — audit structure + grep examples
modsec_audit.log structure (simplified)

An audit record is a multi-part block between markers:

--abcd1234-A--   # request headers / general metadata
--abcd1234-B--   # request POST body / args
--abcd1234-F--   # matched rules / messages (this is where id/msg appears)
--abcd1234-Z--   # end


To quickly find occurrences:

# search by rule id
```sudo grep -n 'id "100001"' /var/log/apache2/modsec_audit.log```

# or by message string
```sudo grep -n "Custom_XSS_Attempt_Blocked" /var/log/apache2/modsec_audit.log```

# show last 200 lines
```sudo tail -n 200 /var/log/apache2/modsec_audit.log | less```


If you prefer short, single-line output (error.log contains shorter lines):

```sudo tail -f /var/log/apache2/error.log```
# or search historic
```sudo grep -i "ModSecurity" /var/log/apache2/error.log```

Common errors we encountered & exact fixes (with commands)
1) Apache fails to start — duplicate rule ID

Problem: Apache error: ModSecurity: Found another rule with the same id or duplicate id.

Cause: CRS or files were included twice (duplicate IncludeOptional), or two configs define same id (e.g., 900990 from CRS and also present in modsecurity.conf).

Fixes:

Ensure security2.conf includes only the explicit includes (no IncludeOptional /etc/modsecurity/*.conf plus the explicit ones). Edit:

```sudo nano /etc/apache2/mods-enabled/security2.conf```


Make it look like:

IncludeOptional /etc/modsecurity/modsecurity.conf
IncludeOptional /etc/modsecurity/crs/crs-setup.conf
IncludeOptional /etc/modsecurity/crs/rules/*.conf
IncludeOptional /etc/modsecurity/local/*.conf


If a duplicate id still appears, search:

```sudo grep -R "id:900990\|900990" /etc/modsecurity -n```


Comment out duplicate definition or remove the duplicate include.

After correction:

```sudo apachectl configtest```
```sudo systemctl restart apache2```

2) Syntax error in custom rules

Problem: SecRule takes two or three arguments or Syntax error on line X.

Fix: Ensure rule syntax is correct and quoting/backslashes are correct. Example valid simple rule:

SecRule ARGS "@rx (?i)<script" "id:100001,phase:2,deny,log,msg:'Custom_XSS_Attempt_Blocked'"


If you used backslashes, be sure they are at end of line and not escaping the quotes incorrectly.

3) No CRS rules loaded / no detections

Check:

```ls -l /etc/modsecurity/crs/rules | head```
```sudo sed -n '1,200p' /etc/apache2/mods-enabled/security2.conf```


If rules folder missing, re-copy the repo rules into /etc/modsecurity/crs/rules and restart Apache.

4) Tail shows nothing during tests

Confirm correct log location:

```ls -l /var/log/apache2/modsec_audit.log /var/log/apache2/error.log```
```sudo tail -n 50 /var/log/apache2/error.log```


Ensure ModSecurity's SecAuditLog points to /var/log/apache2/modsec_audit.log in /etc/modsecurity/modsecurity.conf.

Safe rules lifecycle & best practices

IDs: Reserve a range for your custom rules (100000–199999). Never re-use or collide with CRS IDs.

Tuning: Always start with DetectionOnly mode or pass,log rule action. Tune rules on real requests to reduce false positives.

Deployment: After tuning, change a single rule to deny or set global SecRuleEngine On for blocking.

Management: Keep custom rules in /etc/modsecurity/local/ and version them in git. Use one rule per file (recommended) or one file for a set if easier.

Disable safely: To disable a rule, either remove file or use SecRuleRemoveById <id> in a separate include file — easier than editing many files.

Graceful reload: Use sudo apachectl configtest then sudo systemctl reload apache2 to avoid downtime.

Sudoers for backend: If you plan to have a backend write rule files and reload Apache, give the backend limited sudo permission for apachectl -k graceful only:

# as root, edit /etc/sudoers.d/waf-backend
www-data ALL=(root) NOPASSWD: /usr/sbin/apachectl -k graceful


Then backend can run:

```sudo /usr/sbin/apachectl -k graceful```


Do not give web process full sudo or systemctl blanket access.

Backups, snapshots and demo checklist

VM snapshot: Use VMware → Snapshot → Take Snapshot (name: Pre-Demo-YYYYMMDD). Always snapshot before major changes.

Backup files:

```sudo cp /etc/modsecurity/local/local_rules.conf /root/backup_local_rules.conf.$(date +%F_%T)```
```sudo tar -czvf /root/crs_backup_$(date +%F).tar.gz /etc/modsecurity/crs /etc/modsecurity/local```
```sudo mysqldump -u root -p dvwa > /root/dvwa_db_backup_$(date +%F).sql```


Demo quick script (run and explain):

# Verify services & modules
```sudo systemctl status apache2 --no-pager```
```sudo systemctl status mariadb --no-pager```
```sudo apachectl -M | grep security2```

# Show rule files
```ls -l /etc/modsecurity/crs/rules | wc -l```
```ls -l /etc/modsecurity/local | sed -n '1,100p'```

# Start watching logs
```sudo tail -f /var/log/apache2/modsec_audit.log```
# Perform XSS test on host browser and show log entry.

Appendix — useful scripts & copy-paste snippets
Create local rules file (one command block)
```sudo mkdir -p /etc/modsecurity/local```
```sudo tee /etc/modsecurity/local/local_rules.conf > /dev/null <<'EOF'```
SecRule ARGS "@rx (?i)<script" "id:100001,phase:2,deny,log,msg:'Custom_XSS_Attempt_Blocked'"
SecRule ARGS "@rx (?i)(\bUNION\b|\bSELECT\b.*\bFROM\b|\bOR\s+1=1\b|'\-\-)" "id:100002,phase:2,pass,log,msg:'Custom_SQLi_Detected'"
SecRule REQUEST_HEADERS:Content-Disposition "@rx (?i)filename=.*\.(php|phtml|jsp|asp|aspx|exe|sh|pl|cgi)\b" "id:100003,phase:2,deny,status:403,log,msg:'Custom_Blocked_Upload_Ext'"
EOF
```sudo chown root:root /etc/modsecurity/local/local_rules.conf```
```sudo chmod 644 /etc/modsecurity/local/local_rules.conf```

Toggle DetectionOnly <-> On quickly
# DetectionOnly
```sudo sed -i 's/SecRuleEngine On/SecRuleEngine DetectionOnly/' /etc/modsecurity/modsecurity.conf```
```sudo apachectl configtest && sudo systemctl reload apache2```

# Back to On
```sudo sed -i 's/SecRuleEngine DetectionOnly/SecRuleEngine On/' /etc/modsecurity/modsecurity.conf```
```sudo apachectl configtest && sudo systemctl reload apache2```

Search audit for rule IDs/messages
```sudo grep -n 'id "100001"' /var/log/apache2/modsec_audit.log```
```sudo grep -n "Custom_XSS_Attempt_Blocked" /var/log/apache2/modsec_audit.log```

Quick curl tests
curl -i "http://<VM_IP>/dvwa/vulnerabilities/xss_r/?name=%3Cscript%3Ealert(1)%3C%2Fscript%3E"
curl -i "http://<VM_IP>/dvwa/vulnerabilities/sqli/?id=1'%20OR%20'1'='1"
curl -i -X POST -F "uploaded=@/etc/hosts;filename=test.php" "http://<VM_IP>/dvwa/vulnerabilities/upload/"

Final notes — why this lab matters

This lab reproduces the exact flow of a WAF in front of a web application: traffic → inspection (ModSecurity) → rules → action (log/deny) → logs.

You now have a modular stack: Apache + ModSecurity/CRS + application (DVWA) + custom rules. This is sufficient to implement a demonstration full-stack WAF dashboard later (backend reads/parses logs, writes rule files, toggles rule state).

Always keep safety in mind: rule editing and sudo operations should be protected; only give the minimum privileges to a backend process.

#!/usr/bin/env python3
"""
wp_audit.py — WordPress Security & Recon Scanner v2
Path checks, passive plugin detection, version fingerprinting,
and vulnerability matching against a built-in CVE wordlist.

Usage:
  python wp_audit.py --url https://target.com
  python wp_audit.py --url https://target.com --proxy 127.0.0.1:8080 --random-user-agent
  python wp_audit.py --url https://target.com --only CRIT --output report.json
  python wp_audit.py --url https://target.com --vuln-db wp_plugins_vuln.txt
  python wp_audit.py --url https://target.com --skip-paths --skip-enum

External paths file:
  /custom-path/ | MED | Custom path label

External plugin vuln DB:
  slug | SEV | Name | vuln_below | fixed | CVE | description

  Stuff I want to add:
  Compressed DB To open at runtime instead of this in-script db
  Checks for URL's in "index of" listings like wp-content/uploads so you don't have to manually check
  Easier DB Management
  A will to live (jk I've got one)
  Randomization of paths (forgot if I already added this or not)
"""
import hashlib
import asyncio
import argparse
import random
import json
import re
import sys
from datetime import datetime
from pathlib import Path

try:
    import httpx
except ImportError:
    print("[-] httpx not found.  pip install httpx packaging")
    sys.exit(1)
try:
    from packaging.version import Version, InvalidVersion
except ImportError:
    print("[-] packaging not found.  pip install packaging")
    sys.exit(1)

# ──────────────────────────────────────────────────────────────
#  Colour helpers
# ──────────────────────────────────────────────────────────────
C = {
    "reset": "\033[0m",
    "crit":  "\033[91m",
    "high":  "\033[93m",
    "med":   "\033[94m",
    "info":  "\033[96m",
    "ok":    "\033[92m",
    "dim":   "\033[2m",
    "bold":  "\033[1m",
    "yellow": "\033[93m", # Add this line
}
SEV_COLOR = {"CRIT": C["crit"], "HIGH": C["high"], "MED": C["med"], "INFO": C["info"]}

def col(sev, text):
    return f"{SEV_COLOR.get(sev.upper(), '')}{text}{C['reset']}"

def hdr(title):
    print(f"\n{C['bold']}  ── {title} {'─'*(52-len(title))}{C['reset']}")

def banner(url, threads, throttle, modes):
    print(f"""
{C['bold']}╔══════════════════════════════════════════════════════╗
║        WP Security & Recon Scanner  v2               ║
╚══════════════════════════════════════════════════════╝{C['reset']}
  Target   : {C['ok']}{url}{C['reset']}
  Threads  : {threads}   Throttle : {throttle}s
  Modes    : {', '.join(modes)}
  Started  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
""")

# ──────────────────────────────────────────────────────────────
#  Built-in path list
#  Format: (path, severity, label, category)
# ──────────────────────────────────────────────────────────────
BUILTIN_PATHS = [
    #  1. RECONNAISSANCE & STUFF 
    ("/readme.html",                          "MED",     "WP readme (version disclosure)",          "recon"),
    ("/license.txt",                          "MED",     "WP license.txt (version disclosure)",      "recon"),
    ("/wp-includes/js/wp-embed.min.js",       "MED",      "wp-embed.min.js (version fingerprint)",    "recon"),
    ("/robots.txt",                           "INFO",     "robots.txt (hidden path hints)",           "recon"),
    ("/wp-sitemap.xml",                       "INFO",     "WP sitemap (path/post disclosure)",        "recon"),
    ("/sitemap_index.xml",                    "INFO",     "Sitemap index",                            "recon"),
    ("/.dockerenv",                           "INFO",     "Docker environment detected",              "recon"),
    ("/wp-content/wflogs/ips.php",            "MED",      "Wordfence IP logs",                        "recon"),
    ("/xmlrpc.php",                           "HIGH",     "XML-RPC endpoint",                         "recon"),
    ("/.well-known/security.txt",             "INFO",     "Security contact info",                    "recon"),
    ("/.gitignore",                           "INFO",     "Reveals hidden file/folder structure",     "recon"),
    ("/README.md",                            "MED",      "Project instructions (often has creds)",    "recon"),
    ("/.mailmap",                             "INFO",     "Git mailmap (Developer emails)",           "recon"),
    ("/search",                               "INFO",     "Search Bar",                               "recon"),
    
    #  2. REST API & ENUM 
    ("/wp-json/",                             "INFO",     "REST API root (endpoint enumeration)",     "recon"),
    ("/wp-json/wp/v2/types",                  "INFO",     "REST API post types enumeration",          "recon"),
    ("/wp-json/wp/v2/users",                  "HIGH",     "REST API user listing (unauthenticated)",  "recon"),
    ("/wp-json/wp/v2/posts",                  "INFO",     "REST API posts listing",                   "recon"),
    ("/wp-json/wp/v2/pages",                  "INFO",     "REST API pages listing",                   "recon"),
    ("/wp-json/wp/v2/media",                  "INFO",     "REST API media listing",                   "recon"),
    ("/feed/",                                "INFO",     "RSS feed (generator tag w/ version)",      "recon"),
    ("/wp-json/wp/v2/types/attachment/",      "INFO",      "REST API attachments listing",             "recon"),
    ("/comments/feed/",                       "INFO",     "Comments RSS feed (version disclosure, user comments)",   "recon"),
    ("/?feed=rss2",                           "INFO",     "Fallback RSS2 feed",                       "recon"),
    ("/?feed=atom",                           "INFO",     "Fallback Atom feed",                       "recon"),
    ("/?author=1",                            "HIGH",     "Author archive 1 (user enum)",             "users"),
    ("/?author=2",                            "HIGH",     "Author archive 2 (user enum)",             "users"),
    ("/?author=3",                            "MED",      "Author archive 3 (user enum)",             "users"),
    ("/wp-json/wp/v2/users/1",                "HIGH",     "Direct user 1 metadata leak",              "users"),
    ("/?rest_route=/wp/v2/users",             "HIGH",     "REST API bypass for user enum",            "users"),
    ("/wp-json/oembed/1.0/embed?url=...",      "MED",      "OEmbed provider leak",                     "recon"),
    ("/graphql",                              "MED",      "GraphQL Endpoint (Query Injection)",       "recon"),
    ("/swagger-ui.html",                      "INFO",     "Swagger API documentation",                "recon"),
    ("/wp-json/wp/v2/settings",               "HIGH",     "WP Settings via REST (Admin only?)",       "sensitive"),
    

    #  3. SENSITIVE CONFIGURATION LEAKS 
    ("/wp-content/plugins/wp-file-manager/lib/php/connector.minimal.php", "CRITICAL", "CVE-2020-25213",   "recon"),
    ("/wp-config.php",                        "CRITICAL", "wp-config.php (DB credentials)",           "sensitive"),
    ("/wp-config.php.bak",                    "CRITICAL", "wp-config.php.bak backup",               "sensitive"),
    ("/wp-config.php~",                       "CRITICAL", "wp-config.php~ editor temp",               "sensitive"),
    ("/wp-config.php.old",                    "CRITICAL", "wp-config.php.old",                       "sensitive"),
    ("/wp-config.php.orig",                   "CRITICAL", "wp-config.php.orig",                      "sensitive"),
    ("/wp-config.php.save",                   "CRITICAL", "wp-config.php.save",                      "sensitive"),
    ("/wp-config.php.txt",                    "CRITICAL", "wp-config.php exposed as text",           "sensitive"),
    ("/wp-config.php.swp",                    "CRITICAL", "Vim swap file (wp-config leak)",          "sensitive"),
    ("/wp-config-sample.php",                 "MED",      "wp-config-sample.php",                     "sensitive"),
    ("/.env",                                 "CRITICAL", ".env file (credential leak)",              "sensitive"),
    ("/.env.local",                           "CRITICAL", ".env.local",                              "sensitive"),
    ("/.env.backup",                          "CRITICAL", ".env.backup",                             "sensitive"),
    ("/.htaccess",                            "HIGH",     "/.htaccess readable",                      "sensitive"),
    ("/.user.ini",                            "HIGH",     "Custom PHP settings leak",                 "sensitive"),
    ("/.npmrc",                               "CRITICAL", "NPM config (Auth Tokens)",                 "sensitive"),
    ("/docker-compose.yml",                   "HIGH",     "Docker Compose structure leak",            "sensitive"),
    ("/wp-config.php.dist",                    "MED",      "Default config template (minor leak)",     "sensitive"),
    ("/web.config",                           "MED",      "IIS Server configuration leak",            "sensitive"),
    ("/Dockerfile",                           "HIGH",     "Infrastructure setup leak",                "sensitive"),
    ("/.github/workflows/main.yml",            "HIGH",     "GitHub Actions workflow (CI/CD leak)",     "sensitive"),
    ("/.aws/credentials",                     "CRITICAL", "AWS Credentials file",                     "sensitive"),
    ("/.npmrc",                               "CRITICAL", "NPM Registry Auth Tokens",                 "sensitive"),

    #  4. ACCESS KEYS & HISTORY 
    ("/.vscode/sftp.json",                    "CRITICAL", "VSCode SFTP (Plaintext Credentials)",      "sensitive"),
    ("/.ssh/id_rsa",                          "CRITICAL", "SSH Private Key exposed",                 "sensitive"),
    ("/.ssh/authorized_keys",                 "CRITICAL", "SSH Authorized Keys exposed",             "sensitive"),
    ("/.bash_history",                        "HIGH",     "Bash History (command leak)",              "sensitive"),
    ("/.mysql_history",                       "HIGH",     "MySQL History (DB query leak)",             "sensitive"),
    ("/.git/config",                          "CRITICAL", ".git/config exposed",                     "sensitive"),
    ("/.git/HEAD",                            "CRITICAL", ".git/HEAD exposed",                       "sensitive"),
    ("/.svn/entries",                         "CRITICAL", ".svn/entries exposed",                    "sensitive"),

    #  5. LOGS & DEBUGGING 
    ("/phpinfo.php",                          "HIGH",     "PHP Info (Server/Env leak)",               "sensitive"),
    ("/info.php",                             "HIGH",     "PHP Info (Server/Env leak)",               "sensitive"),
    ("/error_log",                            "HIGH",     "PHP error_log in webroot",                 "sensitive"),
    ("/debug.log",                            "HIGH",     "debug.log in webroot",                     "sensitive"),
    ("/wp-content/debug.log",                 "HIGH",     "WP debug.log",                             "sensitive"),
    ("/wp-content/debug.log.1",               "HIGH",     "Rotated WP debug log",                     "sensitive"),
    ("/access_log",                           "MED",      "Server Access Log",                         "sensitive"),
    ("/error.log",                            "MED",      "Server Error Log",                          "sensitive"),
    ("/wp-content/cache/logs/",               "MED",      "Cached plugin logs",                        "sensitive"),
    ("/wp-content/uploads/wp-mail-log/",      "HIGH",     "WP Mail Log (Email/PII leak)",             "sensitive"),
    ("/wp-content/uploads/wp-all-import/logs/","MED",      "WP All Import Logs (PII leak)",            "sensitive"),
    ("/wp-content/uploads/wc-logs/",          "HIGH",     "WooCommerce transaction/error logs",       "sensitive"),
    ("/wp-content/debug-log.php",             "HIGH",     "Commonly renamed log file",                "sensitive"),
    ("/wp-content/uploads/wpforms/",          "MED",      "WPForms submission data/logs",             "sensitive"),
    ("/wp-content/debug.log.old",             "HIGH",     "Old rotated debug logs",                   "sensitive"),
    ("/wp-content/wp-security-audit-log/",    "MED",      "Security Audit Log directory",             "sensitive"),

    #  6. BACKUPS & DATABASE DUMPS 
    ("/db.sql",                               "CRITICAL", "db.sql in webroot",                        "backup"),
    ("/database.sql",                         "CRITICAL", "database.sql in webroot",                  "backup"),
    ("/dump.sql",                             "CRITICAL", "dump.sql in webroot",                      "backup"),
    ("/wp.sql",                               "CRITICAL", "wp.sql in webroot",                        "backup"),
    ("/sql.sql",                              "CRITICAL", "sql.sql in webroot",                       "backup"),
    ("/data.sql",                             "CRITICAL", "data.sql in webroot",                      "backup"),
    ("/mysql.sql",                            "CRITICAL", "mysql.sql in webroot",                     "backup"),
    ("/wp-content/mysql.sql",                 "CRITICAL", "MySQL dump in wp-content",                  "backup"),
    ("/wp-content/uploads/backup.sql",        "CRITICAL", "SQL backup in uploads",                    "backup"),
    ("/backup.sql.gz",                        "CRITICAL", "Compressed SQL backup",                     "backup"),
    ("/backup.zip",                           "CRITICAL", "backup.zip in webroot",                    "backup"),
    ("/site.zip",                             "CRITICAL", "site.zip in webroot",                      "backup"),
    ("/wp.zip",                               "CRITICAL", "wp.zip in webroot",                        "backup"),
    ("/www.zip",                              "CRITICAL", "Full site backup (www.zip)",                "backup"),
    ("/html.zip",                             "CRITICAL", "Full site backup (html.zip)",               "backup"),
    ("/public_html.zip",                      "CRITICAL", "Full site backup (public_html.zip)",        "backup"),
    ("/db.zip",                               "CRITICAL", "db.zip backup",                             "backup"),
    ("/backup.tar.gz",                        "CRITICAL", "Compressed Tarball backup",                 "backup"),
    ("/wp-content/backups/",                  "HIGH",     "Backups directory",                        "backup"),
    ("/wp-content/backup/",                   "HIGH",     "Backup directory (alt)",                   "backup"),
    ("/wp-content/updraft/",                  "HIGH",     "UpdraftPlus backup dir",                   "backup"),
    ("/wp-content/backup-db/",                "HIGH",     "DB backup directory",                      "backup"),
    ("/wp-content/ai1wm-backups/",            "HIGH",     "All-in-One WP Migration backups",           "backup"),
    ("/wp-content/backups-dup-lite/",          "HIGH",     "Duplicator backups folder",                 "backup"),
    ("/old/",                                 "MED",      "Root /old/ directory",                      "backup"),
    ("/backup.tar",                           "CRITICAL", "Uncompressed tarball backup",              "backup"),
    ("/site.tar.gz",                          "CRITICAL", "Full site tarball",                        "backup"),
    ("/temp.sql",                             "CRITICAL", "Temporary DB export",                      "backup"),
    ("/wp-content/uploads/main.sql",          "CRITICAL", "Common misplaced DB dump",                 "backup"),


    #  7. AUTH & DATABASE ADMIN 
    ("/wp-login.php",                         "INFO",     "Login page (brute-force surface)",         "auth"),
    ("/wp-login.php?action=register",         "MED",      "User registration page",                   "auth"),
    ("/wp-login.php?action=lostpassword",     "MED",      "Password reset page",                      "auth"),
    ("/wp-admin/",                            "INFO",     "Admin dashboard (redirect test)",          "auth"),
    ("/wp-admin/admin-ajax.php",              "MED",      "admin-ajax.php (action enumeration)",      "auth"),
    ("/phpmyadmin/",                          "HIGH",     "phpMyAdmin access point",                   "auth"),
    ("/pma/",                                 "HIGH",     "phpMyAdmin shorthand access",               "auth"),
    ("/adminer.php",                          "CRITICAL", "Adminer Tool (Direct DB access)",          "sensitive"),
    ("/wp-json/wp/v2/users/1/application-passwords", "HIGH", "App passwords user 1",                "auth"),
    ("/wp-json/wp/v2/users/2/application-passwords", "HIGH", "App passwords user 2",                "auth"),

    #  8. SCRIPTS & POTENTIAL BACKDOORS 
    ("/wp-admin/install.php",                 "MED",      "Install script (should redirect)",         "scripts"),
    ("/wp-admin/upgrade.php",                 "MED",      "Upgrade script (should redirect)",         "scripts"),
    ("/wp-admin/setup-config.php",            "HIGH",     "Setup-config script",                      "scripts"),
    ("/wp-cron.php",                          "MED",      "WP-Cron (publicly triggerable?)",          "scripts"),
    ("/shell.php",                            "CRITICAL", "Potential Web Shell found",                "scripts"),
    ("/wp-content/uploads/shell.php",         "CRITICAL", "Web Shell in uploads directory",            "scripts"),
    ("/wp-content/plugins/akismet/akismet.php.bak", "HIGH", "Potential disguised backdoor",          "scripts"),
    ("/wp-content/themes/twentytwentyfour/404.php", "MED",  "Modified 404 (Check for edits)",       "scripts"),
    ("/wp-content/plugins/duplicator/installer.php", "HIGH", "Duplicator Installer (Takeover risk)", "scripts"),
    ("/searchrepalce.php",                    "CRITICAL", "Search-Replace-DB script (Takeover)",      "scripts"),
    ("/wp-content/uploads/extract.php",       "CRITICAL", "Unpacker script left by dev",              "scripts"),

    #  9. DIRECTORY LISTING & UPLOADS 
    ("/wp-content/uploads/",                  "HIGH",     "Uploads dir (check for listing)",          "uploads"),
    ("/wp-content/plugins/",                  "HIGH",     "Plugins dir (check for listing)",          "uploads"),
    ("/wp-content/themes/",                   "MED",      "Themes dir (check for listing)",           "uploads"),
    ("/wp-content/",                          "MED",      "wp-content root (check for listing)",      "uploads"),
    ("/wp-includes/",                         "MED",      "wp-includes root (check for listing)",     "uploads"),

    #  10. STAGING, DEV & OS LEAKS 
    ("/staging/",                             "MED",      "/staging/ directory",                      "staging"),
    ("/dev/",                                 "MED",      "/dev/ directory",                          "staging"),
    ("/test/",                                "MED",      "/test/ directory",                         "staging"),
    ("/beta/",                                "MED",      "/beta/ directory",                         "staging"),
    ("/composer.json",                        "INFO",     "composer.json in webroot",                 "staging"),
    ("/composer.lock",                        "INFO",     "composer.lock in webroot",                 "staging"),
    ("/package.json",                         "INFO",     "package.json in webroot",                  "staging"),
    ("/.DS_Store",                            "MED",      ".DS_Store (OS structure leak)",            "staging"),
    ("/.env.example",                         "INFO",     "Template for env variables",               "sensitive"),
    ("/.user.ini",                            "HIGH",     "Custom PHP settings (bypass potential)",   "sensitive"),
    ("/.editorconfig",                        "INFO",     "Dev environment preferences",              "staging"),
    ("/yarn.lock",                            "INFO",     "Yarn dependency lock (version leak)",      "staging"),
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Firefox/140.0",
    "Mozilla/5.0 (X11; Linux x86_64) rv:130.0 Gecko/20100101 Firefox/130.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:130.0) Gecko/20100101 Firefox/130.0",
]

# ──────────────────────────────────────────────────────────────
#  Built-in plugin vulnerability DB
#  Tuple: (slug, vuln_below, fixed, cve, sev, display_name, description)
#  vuln_below = first SAFE version (installed < vuln_below → vulnerable)
#  Use "all" for unpatched / no fix available
# ──────────────────────────────────────────────────────────────
BUILTIN_VULN_DB = [
    ("wp-file-manager",          "6.9",      "6.9",      "CVE-2020-25213", "CRIT", "WP File Manager",               "Unauthenticated RCE via elFinder (mass exploited)"),
    ("wp-file-manager",          "6.4",      "6.4",      "CVE-2020-12832", "CRIT", "WP File Manager",               "Arbitrary file upload unauthenticated"),
    ("advanced-file-manager",    "5.1.5",    "5.1.5",    "CVE-2023-2068",  "HIGH", "Advanced File Manager",         "Auth file upload → RCE"),
    ("elementor",                "3.1.4",    "3.1.4",    "CVE-2021-3622",  "CRIT", "Elementor",                     "Authenticated arbitrary file upload → RCE"),
    ("elementor",                "3.12.2",   "3.12.2",   "CVE-2023-32243", "HIGH", "Elementor",                     "Privilege escalation via password reset (no auth)"),
    ("elementor",                "3.21.6",   "3.21.6",   "CVE-2024-4671",  "HIGH", "Elementor",                     "Stored XSS via SVG upload"),
    ("elementor-pro",            "3.11.7",   "3.11.7",   "CVE-2023-2122",  "CRIT", "Elementor Pro",                 "Unauthenticated arbitrary file upload → RCE"),
    ("elementor-pro",            "3.18.2",   "3.18.2",   "CVE-2024-2117",  "HIGH", "Elementor Pro",                 "Stored XSS (contributor+)"),
    ("woocommerce",              "3.6.5",    "3.6.5",    "CVE-2019-20041", "CRIT", "WooCommerce",                   "PHP object injection via order meta"),
    ("woocommerce",              "6.6.1",    "6.6.1",    "CVE-2022-21661", "CRIT", "WooCommerce",                   "SQL injection via WP_Query (mass exploited)"),
    ("woocommerce",              "7.8.3",    "7.8.3",    "CVE-2023-28121", "HIGH", "WooCommerce",                   "Auth bypass via header injection"),
    ("woocommerce-payments",     "5.6.2",    "5.6.2",    "CVE-2023-28121", "CRIT", "WooCommerce Payments",          "Unauthenticated privilege escalation to admin"),
    ("woocommerce-blocks",       "11.1.1",   "11.1.1",   "CVE-2023-3326",  "HIGH", "WooCommerce Blocks",            "Sensitive order data exposure via REST API"),
    ("wordpress-seo",            "15.1.3",   "15.1.3",   "CVE-2021-25118", "HIGH", "Yoast SEO",                     "Sensitive data exposure via REST API"),
    ("wordpress-seo",            "21.1.0",   "21.1.0",   "CVE-2023-1892",  "MED",  "Yoast SEO",                     "Open redirect"),
    ("contact-form-7",           "5.3.2",    "5.3.2",    "CVE-2020-35489", "CRIT", "Contact Form 7",                "Unrestricted file upload → RCE"),
    ("contact-form-7",           "5.8.4",    "5.8.4",    "CVE-2023-6449",  "HIGH", "Contact Form 7",                "Stored XSS via uploaded filenames"),
    ("w3-total-cache",           "0.9.7.3",  "0.9.7.3",  "CVE-2019-6715",  "CRIT", "W3 Total Cache",                "SSRF + unauthenticated arbitrary file read"),
    ("w3-total-cache",           "2.2.8",    "2.2.8",    "CVE-2023-6933",  "HIGH", "W3 Total Cache",                "Sensitive data exposure via service worker config"),
    ("w3-total-cache",           "2.7.2",    "2.7.2",    "CVE-2024-12365", "HIGH", "W3 Total Cache",                "SSRF via server info endpoint (subscriber+)"),
    ("wordfence",                "7.5.5",    "7.5.5",    "CVE-2021-39202", "HIGH", "Wordfence",                     "Reflected XSS in login page protection"),
    ("wordfence",                "7.11.3",   "7.11.3",   "CVE-2023-2536",  "MED",  "Wordfence",                     "Sensitive data logging of passwords"),
    ("all-in-one-seo-pack",      "4.1.5.3",  "4.1.5.3",  "CVE-2021-25036", "CRIT", "All in One SEO",                "Authenticated SQLi (subscriber+)"),
    ("all-in-one-seo-pack",      "4.1.5.3",  "4.1.5.3",  "CVE-2021-25037", "HIGH", "All in One SEO",                "Reflected XSS"),
    ("akismet",                  "5.0.1",    "5.0.1",    "CVE-2022-4226",  "MED",  "Akismet Anti-Spam",             "Stored XSS via comment form"),
    ("gravityforms",             "2.4.21",   "2.4.21",   "CVE-2021-38342", "CRIT", "Gravity Forms",                 "Arbitrary file upload → RCE"),
    ("gravityforms",             "2.7.3",    "2.7.3",    "CVE-2023-28782", "HIGH", "Gravity Forms",                 "SQL injection via form metadata"),
    ("gravityforms",             "2.8.4",    "2.8.4",    "CVE-2024-3689",  "HIGH", "Gravity Forms",                 "Reflected XSS"),
    ("ninja-forms",              "3.6.26",   "3.6.26",   "CVE-2022-34867", "CRIT", "Ninja Forms",                   "Unauthenticated email/code injection"),
    ("ninja-forms",              "3.7.1",    "3.7.1",    "CVE-2023-37979", "HIGH", "Ninja Forms",                   "Reflected XSS"),
    ("wpforms-lite",             "1.7.9",    "1.7.9",    "CVE-2023-2950",  "HIGH", "WPForms Lite",                  "Stored XSS via form entry fields"),
    ("wpforms-lite",             "1.9.2.3",  "1.9.2.3",  "CVE-2024-11205", "HIGH", "WPForms Lite",                  "IDOR — payment data exposure"),
    ("jetpack",                  "12.1.1",   "12.1.1",   "CVE-2023-2996",  "CRIT", "Jetpack",                       "Unauthenticated stored XSS via contact form"),
    ("jetpack",                  "13.3.1",   "13.3.1",   "CVE-2024-2716",  "HIGH", "Jetpack",                       "Auth bypass in Jetpack SSO"),
    ("wp-super-cache",           "1.7.2",    "1.7.2",    "CVE-2021-24312", "HIGH", "WP Super Cache",                "Stored XSS in cached content"),
    ("wp-super-cache",           "1.7.4",    "1.7.4",    "CVE-2021-33203", "HIGH", "WP Super Cache",                "Path traversal in admin"),
    ("duplicator",               "1.3.28",   "1.3.28",   "CVE-2020-11738", "CRIT", "Duplicator",                    "Unauthenticated arbitrary file read (wp-config)"),
    ("duplicator",               "1.5.7.1",  "1.5.7.1",  "CVE-2023-4288",  "HIGH", "Duplicator",                    "Directory traversal"),
    ("updraftplus",              "1.22.24",  "1.22.24",  "CVE-2022-0633",  "HIGH", "UpdraftPlus Backup",            "Subscriber+ backup download"),
    ("updraftplus",              "1.23.11",  "1.23.11",  "CVE-2023-32960", "HIGH", "UpdraftPlus Backup",            "Reflected XSS"),
    ("wp-fastest-cache",         "1.2.2",    "1.2.2",    "CVE-2023-6063",  "CRIT", "WP Fastest Cache",              "Unauthenticated SQL injection"),
    ("wp-fastest-cache",         "1.2.7",    "1.2.7",    "CVE-2024-1022",  "HIGH", "WP Fastest Cache",              "Stored XSS"),
    ("redux-framework",          "4.2.11",   "4.2.11",   "CVE-2021-38314", "HIGH", "Redux Framework",               "Unauthenticated sensitive data disclosure"),
    ("redux-framework",          "4.4.17",   "4.4.17",   "CVE-2023-51474", "HIGH", "Redux Framework",               "Stored XSS (contributor+)"),
    ("advanced-custom-fields",   "5.12.3",   "5.12.3",   "CVE-2022-34797", "HIGH", "Advanced Custom Fields",        "Reflected XSS"),
    ("advanced-custom-fields",   "6.1.6",    "6.1.6",    "CVE-2023-30777", "HIGH", "Advanced Custom Fields",        "Reflected XSS (admin+)"),
    ("advanced-custom-fields-pro","6.1.6",   "6.1.6",    "CVE-2023-30777", "HIGH", "ACF Pro",                       "Reflected XSS (admin+)"),
    ("ultimate-member",          "2.6.6",    "2.6.6",    "CVE-2023-3460",  "CRIT", "Ultimate Member",               "Unauthenticated privilege escalation to admin"),
    ("ultimate-member",          "2.8.3",    "2.8.3",    "CVE-2024-1071",  "HIGH", "Ultimate Member",               "SQL injection (unauthenticated)"),
    ("ultimate-member",          "2.8.7",    "2.8.7",    "CVE-2024-6820",  "HIGH", "Ultimate Member",               "Stored XSS"),
    ("litespeed-cache",          "5.7.0.1",  "5.7.0.1",  "CVE-2023-40000", "CRIT", "LiteSpeed Cache",               "Unauthenticated stored XSS"),
    ("litespeed-cache",          "6.3.0.1",  "6.3.0.1",  "CVE-2024-28000", "CRIT", "LiteSpeed Cache",               "Privilege escalation → admin via hash brute force"),
    ("litespeed-cache",          "6.5.0.2",  "6.5.0.2",  "CVE-2024-50550", "HIGH", "LiteSpeed Cache",               "Unauthenticated privilege escalation (Oct 2024)"),
    ("really-simple-ssl",        "9.1.2",    "9.1.2",    "CVE-2024-10924", "CRIT", "Really Simple SSL",             "2FA auth bypass → unauthenticated admin access"),
    ("popup-builder",            "4.2.3",    "4.2.3",    "CVE-2023-6000",  "HIGH", "Popup Builder",                 "Stored XSS — widely exploited (Balada injector)"),
    ("popup-builder",            "4.3.4",    "4.3.4",    "CVE-2024-8274",  "HIGH", "Popup Builder",                 "Stored XSS via subscriber"),
    ("essential-addons-for-elementor-lite", "5.4.8", "5.4.8", "CVE-2023-32243", "CRIT", "Essential Addons for Elementor", "Unauthenticated privilege escalation"),
    ("essential-addons-for-elementor-lite", "5.9.11","5.9.11","CVE-2024-3968",  "HIGH", "Essential Addons for Elementor", "Stored XSS"),
    ("sitepress-multilingual-cms","4.6.12",  "4.6.12",   "CVE-2024-6386",  "CRIT", "WPML",                          "Contributor+ RCE via Twig SSTI"),
    ("the-events-calendar",      "6.2.9",    "6.2.9",    "CVE-2024-8275",  "HIGH", "The Events Calendar",           "SQL injection unauthenticated"),
    ("easy-digital-downloads",   "3.1.5",    "3.1.5",    "CVE-2023-51504", "HIGH", "Easy Digital Downloads",        "SQL injection (shop manager+)"),
    ("sfwd-lms",                 "4.6.0",    "4.6.0",    "CVE-2023-3105",  "HIGH", "LearnDash LMS",                 "Insecure direct object reference"),
    ("revslider",                "4.2.0",    "4.2.0",    "CVE-2014-9734",  "CRIT", "Slider Revolution",             "Unauthenticated arbitrary file upload (historical)"),
    ("revslider",                "6.6.11",   "6.6.11",   "CVE-2022-3990",  "HIGH", "Slider Revolution",             "Reflected XSS"),
    ("js_composer",              "6.9.0",    "6.9.0",    "CVE-2022-0219",  "HIGH", "WPBakery Page Builder",         "Stored XSS (contributor+)"),
    ("js_composer",              "7.5.0",    "7.5.0",    "CVE-2024-2366",  "HIGH", "WPBakery Page Builder",         "Stored XSS (author+)"),
    ("formidable",               "6.3.2",    "6.3.2",    "CVE-2023-52122", "HIGH", "Formidable Forms",              "SQL injection (subscriber+)"),
    ("mw-wp-form",               "5.0.3",    "5.0.3",    "CVE-2024-6265",  "CRIT", "MW WP Form",                    "Unauthenticated arbitrary file upload → RCE"),
    ("wp-statistics",            "13.2.8",   "13.2.8",   "CVE-2022-27850", "HIGH", "WP Statistics",                 "Unauthenticated SQL injection"),
    ("wp-user-avatar",           "4.15.9",   "4.15.9",   "CVE-2024-5325",  "HIGH", "WP User Avatar / ProfilePress", "Arbitrary file upload (subscriber+)"),
    ("broken-link-checker",      "2.3.4",    "2.3.4",    "CVE-2023-4260",  "MED",  "Broken Link Checker",           "SSRF via link checking feature"),
    ("insert-headers-and-footers","3.1.0",   "3.1.0",    "CVE-2023-6959",  "HIGH", "Insert Headers and Footers",    "Contributor+ stored XSS"),
    ("google-analytics-for-wordpress","8.14.1","8.14.1", "CVE-2023-3279",  "HIGH", "MonsterInsights",               "Reflected XSS"),
    ("wp-smushit",               "3.12.6",   "3.12.6",   "CVE-2022-2448",  "HIGH", "Smush Image Optimization",      "Unauthenticated SSRF"),
    ("seo-by-rank-math",         "1.0.95.7", "1.0.95.7", "CVE-2020-11514", "CRIT", "Rank Math SEO",                 "Unauthenticated settings change + stored XSS"),
    ("seo-by-rank-math",         "1.0.214",  "1.0.214",  "CVE-2023-32600", "HIGH", "Rank Math SEO",                 "Reflected XSS"),
    ("wp-mail-smtp",             "3.7.0",    "3.7.0",    "CVE-2023-3054",  "HIGH", "WP Mail SMTP",                  "Admin+ arbitrary settings overwrite"),
    ("memberpress",              "1.9.21",   "1.9.21",   "CVE-2022-1985",  "HIGH", "MemberPress",                   "Reflected XSS"),
    ("memberpress",              "1.11.26",  "1.11.26",  "CVE-2024-8522",  "CRIT", "MemberPress",                   "SQL injection (subscriber+)"),
    ("fluentform",               "5.0.8",    "5.0.8",    "CVE-2023-3198",  "HIGH", "Fluent Forms",                  "Stored XSS"),
    ("fluentform",               "5.1.16",   "5.1.16",   "CVE-2024-2771",  "HIGH", "Fluent Forms",                  "SQL injection (subscriber+)"),
    ("buddypress",               "9.1.1",    "9.1.1",    "CVE-2021-21389", "HIGH", "BuddyPress",                    "Privilege escalation to admin"),
    ("buddypress",               "12.4.0",   "12.4.0",   "CVE-2024-5441",  "HIGH", "BuddyPress",                    "Stored XSS (subscriber+)"),
    ("translatepress-multilingual","2.6.0",  "2.6.0",    "CVE-2023-2813",  "HIGH", "TranslatePress",                "Reflected XSS"),
    ("polylang",                 "3.4.4",    "3.4.4",    "CVE-2023-47777", "MED",  "Polylang",                      "Open redirect"),
    ("wp-all-import",            "3.7.1",    "3.7.1",    "CVE-2023-2879",  "CRIT", "WP All Import",                 "Admin+ arbitrary code execution via template tags"),
    ("wp-all-import",            "3.7.6",    "3.7.6",    "CVE-2024-1084",  "HIGH", "WP All Import",                 "Path traversal"),
    ("download-manager",         "3.2.84",   "3.2.84",   "CVE-2023-6327",  "HIGH", "Download Manager",              "Contributor+ arbitrary file read"),
    ("fusion-builder",           "3.11.1",   "3.11.1",   "CVE-2023-2479",  "HIGH", "Avada / Fusion Builder",        "Stored XSS"),
    ("paid-memberships-pro",     "2.9.12",   "2.9.12",   "CVE-2023-23488", "CRIT", "Paid Memberships Pro",          "Unauthenticated SQL injection"),
    ("miniorange-social-login-and-register","7.6.4","7.6.4","CVE-2023-2982","HIGH","miniOrange Social Login",        "Auth bypass via token validation flaw"),
    ("nextend-facebook-connect", "3.1.8",    "3.1.8",    "CVE-2024-1290",  "HIGH", "Nextend Social Login",          "Authentication bypass"),
    ("ai-engine",                "1.9.99",   "1.9.99",   "CVE-2023-51409", "HIGH", "AI Engine (Meow Apps)",         "Unauthenticated arbitrary file upload"),
    ("gpt3-ai-content-generator","1.8.12",   "1.8.12",   "CVE-2024-2383",  "HIGH", "AI Power",                      "SQL injection (subscriber+)"),
    ("divi-builder",             "4.18.0",   "4.18.0",   "CVE-2022-0751",  "HIGH", "Divi Builder",                  "Contributor+ stored XSS"),
    ("divi-builder",             "4.20.3",   "4.20.3",   "CVE-2023-36691", "CRIT", "Divi Builder",                  "Arbitrary file upload (author+)"),
    ("bbpress",                  "2.6.9",    "2.6.9",    "CVE-2021-41183", "HIGH", "bbPress",                       "Stored XSS via forum posts"),
    ("bbpress",                  "2.6.13",   "2.6.13",   "CVE-2024-5635",  "HIGH", "bbPress",                       "Privilege escalation (subscriber+)"),
    ("wp-optimize",              "3.2.18",   "3.2.18",   "CVE-2023-4194",  "HIGH", "WP-Optimize",                   "Subscriber+ cache purge → data exposure"),
    ("tablepress",               "2.1.6",    "2.1.6",    "CVE-2023-2732",  "HIGH", "TablePress",                    "Stored XSS (editor+)"),
    ("give",                        "3.14.1",   "3.14.1",   "CVE-2024-5932",  "CRIT", "GiveWP",                        "Unauthenticated PHP Object Injection → RCE"),
    ("wp-fastest-cache",            "1.2.4",    "1.2.4",    "CVE-2024-43487", "CRIT", "WP Fastest Cache",              "Unauthenticated SQL Injection via cookie"),
    ("avada",                       "7.11.7",   "7.11.7",   "CVE-2024-47314", "CRIT", "Avada Theme",                   "Unauthenticated Arbitrary File Upload → RCE"),
    ("layered-popups",              "6.60",     "6.60",     "CVE-2024-10332", "CRIT", "Layered Popups",                "Unauthenticated SQL Injection (mass exploited)"),
    ("wp-data-access",              "5.5.11",   "5.5.11",   "CVE-2024-11221", "CRIT", "WP Data Access",                "Unauthenticated Privilege Escalation to Admin"),
    ("filebird",                    "6.0.4",    "6.0.4",    "CVE-2024-9543",  "HIGH", "FileBird",                      "Insecure Direct Object Reference (Subscriber+)"),
    ("essential-blocks",            "4.5.4",    "4.5.4",    "CVE-2024-8992",  "HIGH", "Essential Blocks",              "Local File Inclusion (Contributor+)"),
    ("happy-elementor-addons",      "3.11.4",   "3.11.4",   "CVE-2024-7832",  "HIGH", "Happy Addons for Elementor",    "Broken Access Control → Template Hijacking"),
    ("the-events-calendar",         "6.6.4",    "6.6.4",    "CVE-2024-11823", "HIGH", "The Events Calendar",           "Stored XSS via Event Import"),
    ("ai-power",                    "1.8.64",   "1.8.64",   "CVE-2024-10115", "HIGH", "AI Power",                      "Server-Side Request Forgery (SSRF)"),
    ("all-in-one-seo-pack",         "4.7.2",    "4.7.2",    "CVE-2024-52111", "MED",  "All in One SEO",                "Open Redirect via Sitemap"),
    ("wp-security-audit-log",       "5.2.1",    "5.2.1",    "CVE-2024-9001",  "MED",  "WP Activity Log",               "Sensitive Data Disclosure in log files"),
    ("wp-automatic",               "3.92.0",   "3.92.0",   "CVE-2024-27956", "CRIT", "WP Automatic",                  "Unauthenticated SQL Injection → Admin Creation"),
    ("bricks-builder",              "1.9.6",    "1.9.6",    "CVE-2024-25600", "CRIT", "Bricks Builder",               "Unauthenticated Remote Code Execution (RCE)"),
    ("social-warfare",              "4.4.6",    "4.4.6",    "CVE-2024-2144",  "CRIT", "Social Warfare",                "Unauthenticated Stored XSS + Settings Takeover"),
    ("learnpress",                  "4.2.6.5",  "4.2.6.5",  "CVE-2024-24710", "CRIT", "LearnPress",                    "Local File Inclusion (LFI) → RCE"),
    ("master-addons",               "2.1.1",    "2.1.1",    "CVE-2025-1022",  "CRIT", "Master Addons for Elementor",   "Unauthenticated Privilege Escalation to Admin"),
    ("wp-pagebuilder",              "1.2.9",    "1.2.9",    "CVE-2025-0988",  "HIGH", "WP Page Builder",               "Authenticated (Subscriber+) Arbitrary File Upload"),
    ("forminator",                  "1.29.0",   "1.29.0",   "CVE-2024-31077", "HIGH", "Forminator",                    "Unauthenticated SSRF (Internal Network Scan)"),
    ("tutor",                       "2.7.0",    "2.7.0",    "CVE-2024-3944",  "HIGH", "Tutor LMS",                      "Insecure Direct Object Reference (IDOR)"),
    ("wp-user-frontend",            "4.0.5",    "4.0.5",    "CVE-2025-1143",  "HIGH", "WP User Frontend",               "Stored XSS via frontend submission"),
    ("wp-job-manager",              "2.2.0",    "2.2.0",    "CVE-2026-0122",  "HIGH", "WP Job Manager",                "Sensitive Information Disclosure (Admin Logs)"),
    ("backuply",                    "1.2.6",    "1.2.6",    "CVE-2025-2231",  "MED",  "Backuply",                      "Path Traversal (Information Disclosure)"),
    ("wp-google-maps",              "9.0.35",   "9.0.35",   "CVE-2024-4532",  "MED",  "WP Google Maps",                "Reflected XSS via API parameter")
]

# ──────────────────────────────────────────────────────────────
#  Version comparison helper
# ──────────────────────────────────────────────────────────────
def _ver(v):
    """
    Converts a version string into a comparable Version object.
    Includes a fallback to strip non-numeric suffixes (e.g., '1.2.3-alpha' -> '1.2.3').
    """
    try:
        # Attempt standard parsing first
        return Version(str(v).strip())
    except InvalidVersion:
        # Fallback: keep only digits and dots to create a valid version string
        cleaned = re.sub(r"[^0-9.].*$", "", str(v).strip()).rstrip(".")
        try:
            return Version(cleaned) if cleaned else None
        except InvalidVersion:
            return None

def is_vulnerable(installed_str, vuln_below_str):
    """
    Return True if installed < vuln_below.
    vuln_below = fixed version.
    """
    iv = _ver(installed_str)
    vb = _ver(vuln_below_str)
    
    # If either version cannot be parsed, we cannot confirm vulnerability
    if iv is None or vb is None:
        return False
        
    return iv < vb


# ──────────────────────────────────────────────────────────────
#  Scanner class
# ──────────────────────────────────────────────────────────────
class WPScanner:
    def __init__(self, args):
        self.url            = args.url.rstrip("/")
        self.threads        = args.threads
        self.subdomains     = getattr(args, "subdomains", False)
        self.throttle       = args.throttle

        # Tor overides --proxy
        if getattr(args, "tor", False):
            self.use_tor = True
            self.proxy   = "socks5h://127.0.0.1:9050"
        elif args.proxy:
            self.use_tor = False
            self.proxy   = args.proxy
        else:
            self.use_tor = False
            self.proxy   = None

        self.random_ua      = args.random_user_agent
        self.custom_headers = {}
        if args.header:
            for h in args.header:
                if ":" in h:
                    k, v = h.split(":", 1)
                    self.custom_headers[k.strip()] = v.strip()
        
        self.custom_ua      = args.user_agent
        self.only_sev       = args.only.upper() if args.only else None
        self.exclude_codes  = set(args.exclude_codes) if args.exclude_codes else set()
        self.output         = args.output
        self.categories     = [c.lower() for c in args.categories] if args.categories else None
        self.vuln_db_file   = getattr(args, "vuln_db", None)
        self.skip_paths     = getattr(args, "skip_paths", False)
        self.skip_enum      = getattr(args, "skip_enum", False)
        self.skip_passive   = getattr(args, "skip_passive", False)
        self.ext_paths      = getattr(args, "paths", None)
        self.ext_plugins    = getattr(args, "plugins", None)
        
        # Concurrency control
        self.semaphore      = asyncio.Semaphore(self.threads)

        # Findings
        self.path_findings   = []
        self.plugin_findings = []

        # passive detection
        self._RE_PLUGIN = re.compile(r'/wp-content/plugins/([^/ \'\"]+)/')
        self._RE_WP_VER = re.compile(r'content="WordPress ([0-9.]+)"')


        self.checked_paths   = 0
        self.total_paths     = 0
        self.checked_plugins = 0
        self.total_plugins   = 0
        self.wp_version      = None

        # False Positive Check (Hashes first few KB of front page and checks HTTP 200's against it down a bit from here)
        self._homepage_url   = None
        self._homepage_hash  = None

        # Vuln DB: {slug: [(vuln_below, fixed, cve, sev, name, desc), ...]}
        self.vuln_db = {}
        self._load_vuln_db()

        
    # External Vuln DB Load
    def _load_vuln_db(self):
        """Populates the vuln_db with builtin and external data."""
        # Load Builtin entries
        for (slug, vb, fixed, cve, sev, name, desc) in BUILTIN_VULN_DB:
            s_clean = slug.strip().lower()
            self.vuln_db.setdefault(s_clean, []).append((vb, fixed, cve, sev, name, desc))

        if self.vuln_db_file:
            try:
                loaded = 0
                with open(self.vuln_db_file, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#") or "|" not in line:
                            continue
                        parts = [p.strip() for p in line.split("|")]
                        if len(parts) < 7:
                            continue
                        
                        slug, sev, name, vuln_below, fixed, cve, desc = parts[:7]
                        s_clean = slug.lower()
                        self.vuln_db.setdefault(s_clean, []).append(
                            (vuln_below, fixed, cve, sev.upper(), name, desc)
                        )
                        loaded += 1
                
                total = sum(len(v) for v in self.vuln_db.values())
                print(f"  {C['ok']}[+]{C['reset']} Loaded {self.vuln_db_file}: "
                      f"{loaded} entries ({total} total in DB)")
            except FileNotFoundError:
                print(f"  {C['dim']}[-] vuln-db not found: {self.vuln_db_file}{C['reset']}")
            except Exception as e:
                print(f"  {C['crit']}[-]{C['reset']} Error loading vuln-db: {e}")


    # Matches the plugins found with the vulnerability DB
    def _match_vulns(self, slug, version_str):
        """Matches a detected plugin/version against the loaded database."""
        hits = []
        s_clean = slug.strip().lower()
        
        for (vuln_below, fixed, cve, sev, name, desc) in self.vuln_db.get(s_clean, []):
            # Case 1: All versions are vulnerable
            if str(vuln_below).lower() == "all":
                hits.append((cve, sev, name, desc, fixed, vuln_below))
            
            # Case 2: Version comparison
            elif version_str and is_vulnerable(version_str, vuln_below):
                hits.append((cve, sev, name, desc, fixed, vuln_below))
        
        return hits

    # HTTP helper stuff
    def _ua(self):
        """Returns the appropriate User-Agent string based on configuration."""
        if self.custom_ua:
            return self.custom_ua
        # USER_AGENTS should be a list defined globally
        return random.choice(USER_AGENTS) if self.random_ua else USER_AGENTS[0]

    async def _get(self, client, url, follow=False):
        """Centralized GET requester with throttling and header management."""
        try:
            # 1. Handle Throttling Logic
            if self.throttle:
                delay = 0.1
                if isinstance(self.throttle, str) and "," in self.throttle:
                    try:
                        t_min, t_max = map(float, self.throttle.split(","))
                        delay = random.uniform(t_min, t_max)
                    except ValueError:
                        pass
                else:
                    try:
                        delay = float(self.throttle)
                    except ValueError:
                        pass
                if delay > 0:
                    await asyncio.sleep(delay)

            # Setup Headers (Customize how you want, I tried to make mine look like typical tor Traffic)
            headers = {}
            headers["User-Agent"] = self._ua() if (self.custom_ua or self.random_ua) else "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0"
            headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
            headers["Accept-Language"] = "en-US,en;q=0.5"
            headers["Accept-Encoding"] = "gzip, deflate, br"
            headers["Connection"] = "keep-alive"
            headers["Upgrade-Insecure-Requests"] = "1"
            headers["Sec-Fetch-Dest"] = "document"
            headers["Sec-Fetch-Mode"] = "navigate"
            headers["Sec-Fetch-Site"] = "none"
            headers["Sec-Fetch-User"] = "?1"
            headers.update(self.custom_headers)

            # 3. Execute Request
            return await client.get(
                url,
                headers=headers,
                timeout=12.0,
                follow_redirects=follow,
            )
        except Exception:
            return None


    # overcomplicated way to check the torproject API to check if the TOR IP is legit because it's cooler than using a wrapper
    async def _setup_tor(self, client):
        print(f"  {C['info']}[TOR]{C['reset']} Proxy set to {self.proxy}")
        try:
            resp = await client.get(
                "https://check.torproject.org/api/ip",
                timeout=15.0
            )
            if resp.status_code == 200:
                data   = resp.json()
                ip     = data.get("IP", "unknown")
                is_tor = data.get("IsTor", False)
                if is_tor:
                    print(f"  {C['ok']}[TOR]{C['reset']} Verified Tor exit node — IP: {C['bold']}{ip}{C['reset']}")
                else:
                    # Connected but not through Tor — potential IP leak
                    print(f"  {C['crit']}[TOR]{C['reset']} NOT routing through Tor — IP: {ip}")
                    print(f"  {C['crit']}[TOR]{C['reset']} Aborting to prevent IP leak.{C['reset']}")
                    sys.exit(1)
            else:
                print(f"  {C['crit']}[TOR]{C['reset']} Could not verify Tor — aborting to prevent IP leak.")
                sys.exit(1)
        except Exception as e:
            print(f"  {C['crit']}[TOR]{C['reset']} Verification failed: {e}")
            print(f"  {C['crit']}[TOR]{C['reset']} Aborting to prevent IP leak.{C['reset']}")
            sys.exit(1)

    # Pipe-file loader
    def _load_pipe_file(self, path, as_plugin=False):
        items = []
        if not path:
            return items
        try:
            with open(path) as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if "|" not in line:
                        continue
                    parts = [x.strip() for x in line.split("|")]
                    if len(parts) < 3:
                        continue
                    
                    slug_or_path = parts[0]
                    # Ensure SEV is always uppercase for color matching
                    sev   = parts[1].upper()
                    label = parts[2]
                    # Default to 'external' if no category is provided
                    cat   = parts[3].lower() if len(parts) > 3 else "external"
                    
                    # Formatting logic for plugins vs paths
                    p = f"/wp-content/plugins/{slug_or_path}/" if as_plugin else slug_or_path
                    items.append((p, sev, label, cat))
        except FileNotFoundError:
            print(f"  {C['dim']}[-] File not found: {path}{C['reset']}")
        return items
      
    # Subdomain Check
    async def _query_crt_sh(self, client, domain):
        """Passive subdomain discovery via crt.sh."""
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        subdomains = set()
        try:
            # Note: crt.sh often times out; 25.0s is a good middle ground
            resp = await client.get(url, timeout=25.0)
            if resp.status_code == 200:
                try:
                    data = resp.json()
                    for entry in data:
                        names = entry.get('name_value', '').split('\n')
                        for name in names:
                            # Remove wildcard prefix and normalize
                            clean_name = name.replace('*.', '').lower().strip()
                            if clean_name.endswith(domain) and clean_name != domain:
                                subdomains.add(clean_name)
                except (json.JSONDecodeError, TypeError):
                    # Handle cases where crt.sh returns an error page instead of JSON
                    return []
            return sorted(list(subdomains))
        except Exception as e:
            # We don't want to kill the scan just because crt.sh is down
            print(f"  {C['dim']}[-]{C['reset']} crt.sh discovery skipped: {e}")
            return []

    #  Path checks
    async def _fetch_path(self, client, path, sev, label, cat):
        async with self.semaphore:
            resp = await self._get(client, f"{self.url}{path}")
            self.checked_paths += 1
            if resp is None:
                print(f"  {C['dim']}({self.checked_paths}/{self.total_paths}) scanning...{C['reset']}", end="\r")
                return
            if resp.status_code in (200, 403) and resp.status_code not in self.exclude_codes:
                if resp.status_code == 200 and self._homepage_url is not None:
                    final_url    = str(resp.url)
                    body_hash    = hashlib.md5(resp.text[:4096].encode("utf-8", errors="ignore")).hexdigest()
                    is_redirect  = final_url.rstrip("/") == self._homepage_url.rstrip("/")
                    is_same_body = body_hash == self._homepage_hash
                    if is_redirect or is_same_body:
                        print(f"  {C['dim']}({self.checked_paths}/{self.total_paths}) scanning...{C['reset']}", end="\r")
                        return
                status = "FOUND    " if resp.status_code == 200 else "FORBIDDEN"
                entry = {
                    "path": path, "sev": sev, "label": label,
                    "cat": cat, "status": resp.status_code,
                    "url": f"{self.url}{path}",
                }
                self.path_findings.append(entry)
                print(f"\r  {col(sev, f'[{sev:<4}]')} {status} {resp.status_code}  {label:<50}")
                print(f"          {C['dim']}{self.url}{path}{C['reset']}")
            print(f"  {C['dim']}({self.checked_paths}/{self.total_paths}) scanning...{C['reset']}", end="\r")

    async def run_path_checks(self, client):
        hdr("PATH & FILE CHECKS")
        
        # Merge all task sources
        tasks = list(BUILTIN_PATHS)
        tasks += self._load_pipe_file(self.ext_paths, as_plugin=False)
        tasks += self._load_pipe_file(self.ext_plugins, as_plugin=True)

        # Apply filters
        if self.only_sev:
            tasks = [t for t in tasks if t[1] == self.only_sev]
        if self.categories:
            # Ensure categories are checked in lowercase
            cats = [c.lower() for c in self.categories]
            tasks = [t for t in tasks if t[3].lower() in cats]

        # Deduplicate paths
        seen = set()
        deduped = []
        for t in tasks:
            if t[0] not in seen:
                seen.add(t[0])
                deduped.append(t)

        self.total_paths = len(deduped)
        print(f"  {self.total_paths} paths to check\n")
        await asyncio.gather(*[self._fetch_path(client, *t) for t in deduped])

    # Passive detection from front page
    _RE_PLUGIN  = re.compile(r'/wp-content/plugins/([a-zA-Z0-9_-]+)/',  re.IGNORECASE)
    _RE_THEME   = re.compile(r'/wp-content/themes/([a-zA-Z0-9_-]+)/',   re.IGNORECASE)
    _RE_WP_VER  = re.compile(
        r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']WordPress\s+([\d.]+)["\']',
        re.IGNORECASE
    )
    _RE_WP_VER2 = re.compile(r'(?:ver=|version["\']?\s*[:=]\s*["\']?)([\d]+\.[\d.]+)', re.IGNORECASE)

    # Checks the readme of each plugin for version (e.g. Stable Tag or Version)
    async def _get_version_from_readme(self, client, slug):
        """Fetch /wp-content/plugins/<slug>/readme.txt and parse version."""
        # Ensure the URL is clean (handles trailing slashes)
        base_url = self.url.rstrip('/')
        
        for fname in ("readme.txt", "readme.md"):
            resp = await self._get(client, f"{base_url}/wp-content/plugins/{slug}/{fname}", follow=True)
            if resp and resp.status_code == 200:
                # Optimized regex to handle common readme variations
                patterns = [
                    r'(?i)Stable tag:\s*([v\d][^\s\r\n]+)', 
                    r'(?i)Version:\s*([v\d][^\s\r\n]+)'
                ]
                for pattern in patterns:
                    m = re.search(pattern, resp.text)
                    if m:
                        # Clean version string: remove 'v' prefix, whitespace, and trailing dots
                        return m.group(1).strip().lower().lstrip('v').rstrip(".")
        return None

    async def run_passive_detection(self, client):
        hdr("PASSIVE PLUGIN & VERSION DETECTION")
        print(f"  Fetching page source...\n")

        pages = [self.url.rstrip("/") + "/", self.url.rstrip("/") + "/wp-login.php"]
        # Use a set to automatically handle duplicates across different pages
        unique_slugs = set()

        for page_url in pages:
            resp = await self._get(client, page_url, follow=True)
            if resp is None or resp.status_code not in (200, 403):
                continue
            text = resp.text

            # WP core version check
            if not getattr(self, 'wp_version', None):
                m = self._RE_WP_VER.search(text)
                if m:
                    self.wp_version = m.group(1)

            # Find all plugin slugs
            for slug in self._RE_PLUGIN.findall(text):
                unique_slugs.add(slug)

        # Filter out common directories that aren't plugin slugs
        ignore = {"themes", "plugins", "uploads", "mu-plugins", "languages"}
        slug_set = {s for s in unique_slugs if s not in ignore}

        if getattr(self, 'wp_version', None):
            print(f"  {C['ok']}[WP CORE]{C['reset']} Version: {C['bold']}{self.wp_version}{C['reset']}")

        if not slug_set:
            print(f"  {C['dim']}No plugin slugs found in page source.{C['reset']}")
            return

        print(f"  Detected {len(slug_set)} plugin slug(s) in source. Fetching versions...\n")

        async def resolve(slug):
            async with self.semaphore:
                ver = await self._get_version_from_readme(client, slug)
                return slug, ver

        results = await asyncio.gather(*[resolve(s) for s in slug_set])

        for slug, version in sorted(results):
            ver_str = version or "unknown"
            vulns = self._match_vulns(slug, version)

            if vulns:
                worst = ("CRIT" if any(v[1]=="CRIT" for v in vulns) else
                         "HIGH" if any(v[1]=="HIGH" for v in vulns) else
                         "MED"  if any(v[1]=="MED"  for v in vulns) else "INFO")
                
                print(f"  {col(worst, f'[{worst}]')} {slug}  {C['dim']}v{ver_str}{C['reset']}")
                for (cve, sev, name, desc, fixed, _) in vulns:
                    print(f"    {col(sev, '→')} {cve}  {desc}")
                    if fixed and fixed.lower() != "none":
                        print(f"       {C['dim']}Fixed in: {fixed}  |  Installed: v{ver_str}{C['reset']}")
                
                self.plugin_findings.append({
                    "slug": slug, "version": ver_str, "source": "passive",
                    "vulns": [{"cve": v[0], "sev": v[1], "desc": v[3], "fixed": v[4]} for v in vulns],
                })
            else:
                in_db = slug in self.vuln_db
                # If it's in the DB but we couldn't find a version, it's worth a warning
                db_tag = f"  {C['info']}[in vuln DB — no match at v{ver_str}]{C['reset']}" if in_db else ""
                ver_col = C["dim"] if version else C["yellow"] # Yellow for unknown
                
                print(f"  {C['dim']}[-]{C['reset']} {slug}  {ver_col}v{ver_str}{C['reset']}{db_tag}")
                self.plugin_findings.append({
                    "slug": slug, "version": ver_str, "source": "passive", "vulns": [],
                })

    #  Active Plugin enum
    async def _enum_plugin(self, client, slug):
        """Performs active enumeration for a specific plugin slug."""
        async with self.semaphore:
            self.checked_plugins += 1
            print(f"  {C['dim']}({self.checked_plugins}/{self.total_plugins}){C['reset']} {slug:<45}", end="\r")
            resp = await self._get(client, f"{self.url}/wp-content/plugins/{slug}/")
            
            # Step 2: Validate the response (200 = Directory Index/File, 403 = Forbidden but exists)
            if resp is None or resp.status_code not in (200, 403):
                return

            status_str = "FOUND    " if resp.status_code == 200 else "FORBIDDEN"
            
            # Attempt to fingerprint version and match vulnerabilities
            version = await self._get_version_from_readme(client, slug)
            ver_str = version or "unknown"
            vulns = self._match_vulns(slug, version)

            worst = "INFO"
            display_name = slug
            
            # Use the friendly name from the vuln DB if available
            if self.vuln_db.get(slug):
                # Using index 2 for 'Name' based on your 7-field pipe format
                display_name = self.vuln_db[slug][0][2] 
            
            if vulns:
                worst = ("CRIT" if any(v[1]=="CRIT" for v in vulns) else
                         "HIGH" if any(v[1]=="HIGH" for v in vulns) else
                         "MED"  if any(v[1]=="MED"  for v in vulns) else "INFO")

            # UI Output
            print(f"  {col(worst, f'[{worst}]')} {status_str} {resp.status_code}  "
                  f"{display_name}  {C['dim']}v{ver_str}{C['reset']}")
            print(f"          {C['dim']}{self.url}/wp-content/plugins/{slug}/{C['reset']}")

            if vulns:
                for (cve, sev, name, desc, fixed, _) in vulns:
                    print(f"    {col(sev, '→')} {cve}  {desc}")
                    if fixed and fixed.lower() != "none":
                        print(f"       {C['dim']}Fixed: {fixed}  |  Installed: v{ver_str}{C['reset']}")

            # Store finding for JSON/Text report
            self.plugin_findings.append({
                "slug": slug, 
                "version": ver_str, 
                "source": "enum",
                "status": resp.status_code,
                # Mapping based on your DB: CVE(0), SEV(1), DESC(3), FIXED(4)
                "vulns": [{"cve": v[0], "sev": v[1], "desc": v[3], "fixed": v[4]} for v in vulns],
            })

    async def run_enum(self, client):
        """Coordinates the enumeration phase, skipping plugins already found passively."""
        hdr("WORDLIST PLUGIN ENUMERATION")
        
        all_slugs = list(self.vuln_db.keys())
        # Optimization: Don't re-scan plugins we already found in Phase 2
        passive_found = {f["slug"] for f in self.plugin_findings if f["source"] == "passive"}
        to_check = [s for s in all_slugs if s not in passive_found]
        
        self.total_plugins   = len(to_check)
        self.checked_plugins = 0
        print(f"  {self.total_plugins} plugins to enumerate  "
              f"({C['dim']}{len(passive_found)} skipped — already detected passively{C['reset']})\n")
        await asyncio.gather(*[self._enum_plugin(client, slug) for slug in to_check])

    #  Main
    async def run(self):
        hdr("WP-AUDIT START")

        async with httpx.AsyncClient(
            proxy=httpx.Proxy(url=self.proxy) if self.proxy else None,
            verify=False,
            follow_redirects=True,
        ) as client:

            # Tor verification
            if self.use_tor:
                await self._setup_tor(client)

            # target list
            targets = [self.url]

            # Subdomain Discovery Phase
            if self.subdomains:
                hdr("SUBDOMAIN DISCOVERY")
                # Clean URL to get root domain (e.g., https://example.com/ -> example.com)
                root = self.url.split("//")[-1].split("/")[0]
                found = await self._query_crt_sh(client, root)
                print(f"  {C['info']}[+]{C['reset']} Found {len(found)} subdomains.")
                for sub in found:
                    targets.append(f"https://{sub}")

            # Execution Phase
            for current_target in targets:
                self.url = current_target.rstrip("/")
                print(f"\n{C['bold']}>>> TARGET: {self.url}{C['reset']}")

                # Check if target is alive before heavy scanning
                checker = await self._get(client, self.url, follow=True)
                if checker is None:
                    print(f"  {C['crit']}[-]{C['reset']} Target offline. Skipping.")
                    continue
                print(f"  {C['info']}[*]{C['reset']} Status: {checker.status_code}")
                self._homepage_url  = str(checker.url)
                self._homepage_hash = hashlib.md5(checker.text[:4096].encode("utf-8", errors="ignore")).hexdigest()

                if not self.skip_paths:
                    print(f"\n{C['bold']}  [Part 1/3] Path & File Checks{C['reset']}")
                    await self.run_path_checks(client)
                if not self.skip_passive:
                    print(f"\n{C['bold']}  [Part 2/3] Passive Detection{C['reset']}")
                    await self.run_passive_detection(client)
                if not self.skip_enum:
                    print(f"\n{C['bold']}  [Part 3/3] Plugin Enumeration{C['reset']}")
                    await self.run_enum(client)

        hdr("SCAN COMPLETE")
        self._print_summary()
        if self.output:
            self._save_output()

    #  Summary & output
    def _print_summary(self):
        print(f"\n{'─'*60}")
        print(f"{C['bold']}  Scan complete.{C['reset']}")
        print(f"  Paths checked : {self.checked_paths}")
        print(f"  Path findings : {len(self.path_findings)}")
        vuln_plugins = [p for p in self.plugin_findings if p["vulns"]]
        total_plugins = len(set(p["slug"] for p in self.plugin_findings))
        print(f"  Plugins found : {total_plugins}  ({len(vuln_plugins)} with known CVE matches)\n")

        if self.wp_version:
            print(f"  {C['ok']}WP Core version: {self.wp_version}{C['reset']}")

        if self.path_findings:
            print(f"\n{C['bold']}  Path findings:{C['reset']}")
            by_sev = {}
            for f in self.path_findings:
                by_sev.setdefault(f["sev"], []).append(f)
            for sev in ("CRIT", "HIGH", "MED", "INFO"):
                items = by_sev.get(sev, [])
                if not items:
                    continue
                print(col(sev, f"  [{sev}] {len(items)} finding(s)"))
                for f in items:
                    print(f"    {C['dim']}{f['status']}{C['reset']}  {f['label']}")
                    print(f"         {C['dim']}{f['url']}{C['reset']}")

        # Dedupe plugin vulns
        seen_slugs = set()
        if vuln_plugins:
            print(f"\n{C['bold']}  Vulnerable plugins:{C['reset']}")
            for p in vuln_plugins:
                if p["slug"] in seen_slugs:
                    continue
                seen_slugs.add(p["slug"])
                worst = ("CRIT" if any(v["sev"]=="CRIT" for v in p["vulns"]) else
                         "HIGH" if any(v["sev"]=="HIGH" for v in p["vulns"]) else
                         "MED"  if any(v["sev"]=="MED"  for v in p["vulns"]) else "INFO")
                print(f"  {col(worst, f'[{worst}]')} {p['slug']}  v{p['version']}")
                for v in p["vulns"]:
                    print(f"    {col(v['sev'], '→')} {v['cve']}  {v['desc']}")
                    if v["fixed"] and v["fixed"].lower() != "none":
                        print(f"         {C['dim']}Fixed: {v['fixed']}{C['reset']}")
        print()

    def _save_output(self):
        ext = Path(self.output).suffix.lower()
        try:
            if ext == ".json":
                with open(self.output, "w") as fh:
                    json.dump({
                        "target":          self.url,
                        "wp_version":      self.wp_version,
                        "date":            datetime.now().isoformat(),
                        "path_findings":   self.path_findings,
                        "plugin_findings": self.plugin_findings,
                    }, fh, indent=2)
            else:
                lines = [
                    "WP Security & Recon Scanner v2",
                    f"Target     : {self.url}",
                    f"WP Version : {self.wp_version or 'unknown'}",
                    f"Date       : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                    "=" * 60, "",
                    f"PATH FINDINGS ({len(self.path_findings)})",
                ]
                for sev in ("CRIT", "HIGH", "MED", "INFO"):
                    items = [f for f in self.path_findings if f["sev"] == sev]
                    if not items:
                        continue
                    lines.append(f"[{sev}]")
                    for f in items:
                        lines.append(f"  {f['status']}  {f['label']}")
                        lines.append(f"       {f['url']}")
                vuln_plugins = [p for p in self.plugin_findings if p["vulns"]]
                lines += ["", f"VULNERABLE PLUGINS ({len(vuln_plugins)})"]
                for p in vuln_plugins:
                    lines.append(f"  {p['slug']}  v{p['version']}  [{p['source']}]")
                    for v in p["vulns"]:
                        lines.append(f"    [{v['sev']}] {v['cve']} — {v['desc']}")
                        if v["fixed"] and v["fixed"].lower() != "none":
                            lines.append(f"           Fixed: {v['fixed']}")
                with open(self.output, "w") as fh:
                    fh.write("\n".join(lines))
            print(f"\n  {C['ok']}[+] Report saved → {self.output}{C['reset']}")
        except Exception as e:
            print(f"\n  {C['crit']}[-] Save failed: {e}{C['reset']}")



if __name__ == "__main__":
    # Legal Warning for --help
  
    parser = argparse.ArgumentParser(
        description=(
            "WordPress Intel Scanner\n\n"
            "⚠️  LEGAL WARNING:\n"
            "This tool is for AUTHORIZED security research, bug bounty, or law enforcement use ONLY.\n"
            "Unauthorized scanning of systems may violate local, state, and federal laws.\n"
            "You MUST have prior, explicit, written authorization from the system owner.\n"
            "Failure to comply may result in criminal prosecution and civil liability."
        ),
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
phases:
  paths    — ~70 built-in sensitive path checks
  passive  — fetch homepage source, extract plugin slugs
  enum     — enumerate plugin slugs in vuln DB, detect version

examples:
  python wp-audit.py --url https://target.com
  python wp-audit.py --url https://target.com --only CRIT --output report.json
        """
    )

    # Args
    parser.add_argument("--url",               required=True,           help="Target (https://target.com)")
    parser.add_argument("--subdomains",        action="store_true",     help="Passive subdomain discovery via crt.sh")
    parser.add_argument("--paths",             default=None,            help="Extra paths file")
    parser.add_argument("--user-agent",        default=None,            help="Override User-Agent")
    parser.add_argument("--exclude-codes", nargs="+", type=int, default=[], help="HTTP status codes to exclude (e.g. --exclude-codes 403 404)")
    parser.add_argument("--header",            action="append",         help="Extra header (Key:Value)")
    parser.add_argument("--plugins",           default=None,            help="Extra plugin slugs file")
    parser.add_argument("--threads",           type=int,   default=10,  help="Concurrency (default: 10)")
    parser.add_argument("--vuln-db",           default=None,            help="External vuln DB file")
    parser.add_argument("--throttle",          type=str,   default="0.1", help="Delay (e.g. 0.1)")
    parser.add_argument("--proxy",             default=None,           help="Proxy URL with scheme, e.g. socks5://127.0.0.1:9050 or http://127.0.0.1:8080")
    parser.add_argument("--random-user-agent", action="store_true",     help="Rotate User-Agents")
    parser.add_argument("--only",              default=None,            help="Filter: CRIT|HIGH|MED|INFO")
    parser.add_argument("--categories",        nargs="+",               help="Path categories")
    parser.add_argument("--output",            default=None,            help="Save to file")
    parser.add_argument("--skip-paths",        action="store_true",     help="Skip path checks")
    parser.add_argument("--skip-passive",      action="store_true",     help="Skip passive detection")
    parser.add_argument("--skip-enum",         action="store_true",     help="Skip plugin enumeration")
    parser.add_argument("--tor", action="store_true",                   help="Route through Tor (socks5://127.0.0.1:9050) and verify exit node")
    args = parser.parse_args()
    
    if args.tor and args.proxy:
        parser.error("--tor and --proxy are mutually exclusive")

    # Legal warning in red because IM FANCY LIKE DAT
    print(f"""
    {C['crit']}{C['bold']}┌──────────────────────────────────────────────────────────┐
    │                      LEGAL WARNING                       │
    ├──────────────────────────────────────────────────────────┤
    │  This tool is for AUTHORIZED security testing ONLY.      │
    │  Unauthorized access to computer systems is ILLEGAL.     │
    │  By continuing, you confirm you have WRITTEN PERMISSION. │
    └──────────────────────────────────────────────────────────┘{C['reset']}""")
    confirm = input("Type 'I HAVE AUTHORIZATION' OR 'ACK' to continue: ").strip().lower()
    
    # python101 you can read yourself
    if confirm not in ["i have authorization", "ack"]:
        print("[-] Authorization not confirmed. Exiting.")
        sys.exit(1)

    # This is what the kids call... the main thing
    scanner = WPScanner(args)
    asyncio.run(scanner.run())

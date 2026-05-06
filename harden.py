import http.server
import socketserver
import subprocess
import urllib.parse
import os

PORT = 8088

WHITELIST = [
    "/usr/bin/passwd", "/usr/bin/chfn", "/usr/bin/chsh", "/usr/bin/gpasswd",
    "/usr/bin/newgrp", "/usr/bin/sudo", "/usr/bin/mount", "/usr/bin/umount",
    "/usr/bin/pkexec", "/usr/lib/dbus-1.0/dbus-daemon-launch-helper",
    "/usr/lib/openssh/ssh-keysign", "/usr/bin/at", "/usr/lib/policykit-1/polkit-agent-helper-1"
]

class UltimateHardeningHandler(http.server.SimpleHTTPRequestHandler):

    
    def scan_vulnerabilities(self):
        results = {"world_writable": [], "orphaned": [], "passwordless_accounts": [], "extra_roots": [], "non_shadowed": []}
        results["world_writable"] = subprocess.run("find / -xdev -user root \\( -perm -0002 -a ! -perm -1000 \\) -print 2>/dev/null | head -n 20", shell=True, capture_output=True, text=True).stdout.splitlines()
        results["orphaned"] = subprocess.run("find / -xdev \\( -nouser -o -nogroup \\) -print 2>/dev/null | head -n 20", shell=True, capture_output=True, text=True).stdout.splitlines()
        results["passwordless_accounts"] = subprocess.run("awk -F: '$2 == \"\" { print $1}' /etc/shadow 2>/dev/null", shell=True, capture_output=True, text=True).stdout.splitlines()
        results["extra_roots"] = subprocess.run("awk -F: '{if ($3==0 && $1!=\"root\") print $1 }' /etc/passwd", shell=True, capture_output=True, text=True).stdout.splitlines()
        results["non_shadowed"] = subprocess.run("awk -F: '($2 != \"x\" ) { print $1 }' /etc/passwd", shell=True, capture_output=True, text=True).stdout.splitlines()
        return results

    def scan_suid(self):
        cmd = "find / -perm -4000 -type f 2>/dev/null"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        all_files = result.stdout.splitlines() if result.stdout else []
        return [f for f in all_files if f not in WHITELIST]

    def scan_mounts(self):
        mounts = []
        if os.path.exists('/etc/fstab'):
            with open('/etc/fstab', 'r') as f:
                for line in f:
                    if line.strip() and not line.startswith('#'):
                        parts = line.split()
                        if len(parts) > 1: mounts.append(parts[1])
        return mounts

  
    def do_GET(self):
        vuln_data = self.scan_vulnerabilities()
        suid_files = self.scan_suid()
        existing_mounts = self.scan_mounts()
        target_dirs = ["/boot", "/home", "/var", "/tmp", "/opt", "/usr", "/run/shm"]

        html = f"""
        <!DOCTYPE html>
        <html lang="tr">
        <head>
            <meta charset="utf-8">
            <title>Ultimate Hardening Suite</title>
            <style>
                :root {{ --bg: #0a0a0c; --panel: #111; --border: #222; --accent: #00ff41; --danger: #ff003c; --text: #e0e0e0; }}
                * {{ box-sizing: border-box; font-family: 'Segoe UI', Tahoma, Consolas, sans-serif; }}
                body {{ margin: 0; padding: 0; background: var(--bg); color: var(--text); display: flex; height: 100vh; overflow: hidden; }}
                
                /* Sidebar */
                .sidebar {{ width: 280px; background: #050505; border-right: 1px solid var(--border); display: flex; flex-direction: column; padding: 20px 0; }}
                .logo {{ text-align: center; color: var(--accent); font-size: 1.5rem; font-weight: bold; margin-bottom: 30px; letter-spacing: 1px; border-bottom: 1px solid var(--border); padding-bottom: 20px; }}
                .menu-item {{ padding: 15px 25px; cursor: pointer; color: #888; font-weight: bold; transition: all 0.3s; border-left: 4px solid transparent; }}
                .menu-item:hover {{ background: #1a1a1a; color: #fff; }}
                .menu-item.active {{ background: #111; color: var(--accent); border-left: 4px solid var(--accent); }}
                .mega-btn-container {{ margin-top: auto; padding: 20px; border-top: 1px solid var(--border); }}
                .btn-mega {{ background: var(--accent); color: #000; width: 100%; padding: 15px; border: none; font-weight: bold; font-size: 1rem; cursor: pointer; border-radius: 5px; box-shadow: 0 0 15px rgba(0,255,65,0.2); transition: 0.3s; }}
                .btn-mega:hover {{ background: #00cc33; box-shadow: 0 0 25px rgba(0,255,65,0.4); transform: scale(1.02); }}

                /* Content Area */
                .content {{ flex: 1; padding: 40px; overflow-y: auto; background: var(--bg); }}
                .tab-pane {{ display: none; animation: fadeIn 0.4s; }}
                .tab-pane.active {{ display: block; }}
                @keyframes fadeIn {{ from {{ opacity: 0; transform: translateY(10px); }} to {{ opacity: 1; transform: translateY(0); }} }}
                
                h2 {{ color: #fff; border-bottom: 2px solid var(--accent); padding-bottom: 10px; margin-top: 0; }}
                .section {{ background: var(--panel); border: 1px solid var(--border); padding: 20px; border-radius: 8px; margin-bottom: 25px; }}
                .row {{ display: flex; align-items: center; margin: 10px 0; font-size: 14px; padding: 8px; border-bottom: 1px dashed #222; }}
                .row:hover {{ background: #1a1a1a; }}
                
                input[type="checkbox"] {{ transform: scale(1.4); margin-right: 15px; accent-color: var(--accent); cursor: pointer; }}
                input[type="number"], select {{ background: #000; color: var(--accent); border: 1px solid var(--accent); padding: 5px; margin-left: auto; width: 80px; border-radius: 3px; }}
                
                .btn-generate {{ background: #222; color: var(--accent); border: 1px solid var(--accent); padding: 12px 25px; cursor: pointer; font-weight: bold; border-radius: 5px; transition: 0.3s; margin-top: 15px; float: right; }}
                .btn-generate:hover {{ background: var(--accent); color: #000; }}
                
                .info-text {{ font-size: 12px; color: #888; margin-bottom: 15px; }}
                .danger-text {{ color: var(--danger); font-weight: bold; }}
            </style>
            <script>
                function showTab(tabId, elem) {{
                    document.querySelectorAll('.tab-pane').forEach(el => el.classList.remove('active'));
                    document.getElementById(tabId).classList.add('active');
                    document.querySelectorAll('.menu-item').forEach(el => el.classList.remove('active'));
                    elem.classList.add('active');
                }}
            </script>
        </head>
        <body>
            <form method="POST" id="mainForm" style="display: contents;">
                <!-- Sidebar -->
                <div class="sidebar">
                    <div class="logo">O.S. HARDENING<br><span style="font-size: 12px; color: #888;">ULTIMATE FRAMEWORK</span></div>
                    
                    <div class="menu-item active" onclick="showTab('tab_vuln', this)">🔍 Dosya ve Kullanıcı Zafiyetleri</div>
                    <div class="menu-item" onclick="showTab('tab_suid', this)">🛡️ SUID Temizliği</div>
                    <div class="menu-item" onclick="showTab('tab_master', this)">⚙️ Gelişmiş Sıkılaştırma (SSH/PAM)</div>
                    
                    <div class="mega-btn-container">
                        <button type="submit" formaction="/gen_all" class="btn-mega">TÜMÜNÜ BİRLEŞTİR (TOPLU SCRIPT)</button>
                    </div>
                </div>

                <!-- Main Content -->
                <div class="content">
                    
                    <!-- TAB 1: ZAFİYET TARAMASI -->
                    <div id="tab_vuln" class="tab-pane active">
                        <h2>Sistem Zafiyetleri (Dosya ve Kullanıcılar)</h2>
                        <div class="section">
                            <h3 style="color:#fff;">1. Herkesin Yazabildiği Dosyalar (777)</h3>
                            <div class="info-text">Seçilenlerin izinleri 755 olarak düzeltilir.</div>
                            {''.join([f'<div class="row"><input type="checkbox" name="ww" value="{f}"> {f}</div>' for f in vuln_data["world_writable"]]) or "<div class='row'>Temiz.</div>"}
                        </div>
                        <div class="section">
                            <h3 style="color:#fff;">2. Sahipsiz (Orphaned) Dosyalar</h3>
                            <div class="info-text">Sahipliği root'a devredilir, izni 644 yapılır.</div>
                            {''.join([f'<div class="row"><input type="checkbox" name="orph" value="{f}"> {f}</div>' for f in vuln_data["orphaned"]]) or "<div class='row'>Temiz.</div>"}
                        </div>
                        <div class="section">
                            <h3 style="color:#fff;">3. Parolasız ve Riskli Hesaplar</h3>
                            <div class="info-text danger-text">Parolasızlar kilitlenir (passwd -l). Shadow senkronizasyonu yapılır.</div>
                            {''.join([f'<div class="row"><input type="checkbox" name="pwless" value="{u}"> [Parolasız] {u}</div>' for u in vuln_data["passwordless_accounts"]])}
                            {''.join([f'<div class="row"><input type="checkbox" name="rooters" value="{u}"> [UID 0 Risk] {u}</div>' for u in vuln_data["extra_roots"]])}
                            {''.join([f'<div class="row"><input type="checkbox" name="unshadow" value="{u}"> [Shadow Edilmemiş] {u}</div>' for u in vuln_data["non_shadowed"]])}
                            {(not vuln_data["passwordless_accounts"] and not vuln_data["extra_roots"] and not vuln_data["non_shadowed"]) and "<div class='row'>Riskli kullanıcı bulunamadı.</div>" or ""}
                        </div>
                        <button type="submit" formaction="/gen_vuln" class="btn-generate">SADECE BU BÖLÜMÜN SCRIPTİNİ ÜRET</button>
                    </div>

                    <!-- TAB 2: SUID TEMİZLİĞİ -->
                    <div id="tab_suid" class="tab-pane">
                        <h2>SUID Yetki Temizliği</h2>
                        <div class="section">
                            <div class="info-text">Sistem çalışması için gereken (passwd, sudo vb.) varsayılan dosyalar gizlenmiştir. Kalan şüpheli dosyaları seçin. (chmod u-s uygulanır)</div>
                            {''.join([f'<div class="row"><input type="checkbox" name="suid_f" value="{f}"> {f}</div>' for f in suid_files]) or "<div class='row'>Şüpheli SUID dosyası bulunamadı.</div>"}
                        </div>
                        <button type="submit" formaction="/gen_suid" class="btn-generate">SADECE SUID SCRIPTİNİ ÜRET</button>
                    </div>

                    <!-- TAB 3: MASTER HARDENING -->
                    <div id="tab_master" class="tab-pane">
                        <h2>Gelişmiş Servis ve Çekirdek Sıkılaştırma</h2>
                        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px;">
                            
                            <div class="section">
                                <h3 style="color:#fff;">SSH Yapılandırması</h3>
                                <div class="row"><input type="checkbox" name="ssh_root"> PermitRootLogin <select name="v_root"><option value="no">no</option><option value="yes">yes</option></select></div>
                                <div class="row"><input type="checkbox" name="ssh_empty"> PermitEmptyPasswords <select name="v_empty"><option value="no">no</option></select></div>
                                <div class="row"><input type="checkbox" name="ssh_tries"> MaxAuthTries <input type="number" name="v_tries" value="4"></div>
                                <div class="row"><input type="checkbox" name="ssh_alive"> ClientAliveInterval <input type="number" name="v_alive" value="300"></div>
                            </div>

                            <div class="section">
                                <h3 style="color:#fff;">PAM Parola Politikası</h3>
                                <div class="row"><input type="checkbox" name="pam_min"> Min Uzunluk (minlen) <input type="number" name="v_min" value="8"></div>
                                <div class="row"><input type="checkbox" name="pam_u"> En az 1 Büyük Harf (ucredit)</div>
                                <div class="row"><input type="checkbox" name="pam_d"> En az 1 Rakam (dcredit)</div>
                                <div class="row"><input type="checkbox" name="pam_o"> Özel Karakter (ocredit)</div>
                                <div class="row"><input type="checkbox" name="pam_rem"> Geçmiş Parolalar (remember) <input type="number" name="v_rem" value="2"></div>
                            </div>

                            <div class="section">
                                <h3 style="color:#fff;">Ağ / Çekirdek (Sysctl)</h3>
                                <div class="row"><input type="checkbox" name="net_ipv6"> IPv6 Devre Dışı Bırak</div>
                                <div class="row"><input type="checkbox" name="net_sync"> TCP Syncookies Aktif Et</div>
                                <div class="row"><input type="checkbox" name="net_icmp"> ICMP (Ping) Kapat</div>
                                <div class="row"><input type="checkbox" name="net_aslr"> ASLR (Rastgele Bellek) <select name="v_aslr"><option value="2">2 (Tam)</option><option value="1">1</option></select></div>
                            </div>

                            <div class="section">
                                <h3 style="color:#fff;">Dosya İzinleri & Bütünlük</h3>
                                <div class="row"><input type="checkbox" name="perm_files"> Kritik Dosya İzinleri Düzenle</div>
                                <div class="row"><input type="checkbox" name="perm_cron"> Cron Dizinlerini Sıkılaştır (700)</div>
                                <div class="row"><input type="checkbox" name="check_hash"> Paket Hash Kontrolü (MD5)</div>
                            </div>

                        </div>

                        <div class="section">
                            <h3 style="color:#fff;">Disk (FSTAB) Sıkılaştırma</h3>
                            <div class="info-text">Seçtiğiniz dizine özel güvenlik bayraklarını uygulayın. (Örn: /var için sadece nosuid)</div>
                            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 15px;">
        """

        for mnt in target_dirs:
            is_present = mnt in existing_mounts
            info_text = "Sistemde Var" if is_present else "Hedef Sistem İçin"
            color = "var(--accent)" if is_present else "#666"
            safe_name = "f_" + mnt.replace("/", "_")
            
            html += f"""
                                <div style="border-left: 2px solid {color}; padding-left: 10px; background: #0a0a0c; padding: 10px;">
                                    <div style="font-weight: bold; color: {color}; margin-bottom: 5px;">{mnt} <span style="font-size:10px;">({info_text})</span></div>
                                    <div style="display:flex; gap:10px; font-size: 13px;">
                                        <label><input type="checkbox" name="{safe_name}" value="nodev">nodev</label>
                                        <label><input type="checkbox" name="{safe_name}" value="nosuid">nosuid</label>
                                        <label><input type="checkbox" name="{safe_name}" value="noexec">noexec</label>
                                        <label><input type="checkbox" name="{safe_name}" value="ro">ro</label>
                                    </div>
                                </div>
            """

        html += """
                            </div>
                        </div>
                        <button type="submit" formaction="/gen_master" class="btn-generate">SADECE GELİŞMİŞ SIKILAŞTIRMA SCRIPTİNİ ÜRET</button>
                    </div>

                </div>
            </form>
        </body>
        </html>
        """
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(html.encode())

    
    def gen_vuln_script(self, p):
        s = ["# --- KULLANICI VE DOSYA ZAFIYETLERI ---"]
        for f in p.get('ww', []): s.append(f"chmod 755 {f} && echo '[+] Izin duzeltildi: {f}'")
        for f in p.get('orph', []): s.append(f"chown root:root {f} && chmod 644 {f} && echo '[+] Sahipsiz dosya root yapildi: {f}'")
        for u in p.get('pwless', []): s.append(f"passwd -l {u} && echo '[+] Parolasiz hesap kilitlendi: {u}'")
        for u in p.get('rooters', []): s.append(f"echo '[!] UYARI: UID 0 (Root) olan hesap tespit edildi -> {u} (Manuel inceleyin)'")
        if p.get('unshadow'): s.append("pwconv && echo '[+] Shadow senkronizasyonu yapildi.'")
        return s if len(s) > 1 else []

    def gen_suid_script(self, p):
        s = ["# --- SUID TEMIZLIGI ---"]
        for f in p.get('suid_f', []): s.append(f"chmod -s {f} && echo '[+] SUID kaldirildi: {f}'")
        return s if len(s) > 1 else []

    def gen_master_script(self, p):
        s = ["# --- GELISMIS SERVIS & CEKIRDEK & DISK ---"]
        
        
        if 'ssh_root' in p: s.append(f"sed -i 's/^#\\?PermitRootLogin.*/PermitRootLogin {p['v_root'][0]}/' /etc/ssh/sshd_config")
        if 'ssh_empty' in p: s.append(f"sed -i 's/^#\\?PermitEmptyPasswords.*/PermitEmptyPasswords {p['v_empty'][0]}/' /etc/ssh/sshd_config")
        if 'ssh_tries' in p: s.append(f"sed -i 's/^#\\?MaxAuthTries.*/MaxAuthTries {p['v_tries'][0]}/' /etc/ssh/sshd_config")
        if 'ssh_alive' in p: s.append(f"sed -i 's/^#\\?ClientAliveInterval.*/ClientAliveInterval {p['v_alive'][0]}/' /etc/ssh/sshd_config")
        if any(k in p for k in ['ssh_root', 'ssh_empty', 'ssh_tries', 'ssh_alive']): s.append("systemctl restart ssh && echo '[+] SSH yapilandirildi.'")

        
        pam_opts = []
        if 'pam_min' in p: pam_opts.append(f"minlen={p['v_min'][0]}")
        if 'pam_u' in p: pam_opts.append("ucredit=-1")
        if 'pam_d' in p: pam_opts.append("dcredit=-1")
        if 'pam_o' in p: pam_opts.append("ocredit=-1")
        if 'pam_rem' in p: pam_opts.append(f"remember={p['v_rem'][0]}")
        if pam_opts: s.append(f"sed -i '/pam_pwquality.so/c\\password requisite pam_pwquality.so retry=3 {' '.join(pam_opts)}' /etc/pam.d/common-password && echo '[+] PAM politikalari uygulandi.'")

        
        if 'net_ipv6' in p: s.append("sysctl -w net.ipv6.conf.all.disable_ipv6=1 && sysctl -w net.ipv6.conf.default.disable_ipv6=1")
        if 'net_sync' in p: s.append("sysctl -w net.ipv4.tcp_syncookies=1")
        if 'net_icmp' in p: s.append("sysctl -w net.ipv4.icmp_echo_ignore_all=1")
        if 'net_aslr' in p: s.append(f"sysctl -w kernel.randomize_va_space={p['v_aslr'][0]}")

        
        if 'perm_files' in p:
            s.append("chmod 644 /etc/passwd /etc/group /etc/hosts /etc/hostname /etc/issue /etc/issue.net")
            s.append("chmod 640 /etc/shadow /etc/gshadow /var/log/auth.log 2>/dev/null")
            s.append("chmod 600 /etc/ssh/sshd_config /etc/crontab /etc/securetty /boot/grub/grub.cfg 2>/dev/null")
        if 'perm_cron' in p: s.append("chmod 700 /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly")
        if 'check_hash' in p: s.append("echo '[*] Paket hash kontrolu...'; md5sum -c /var/lib/dpkg/info/*.md5sums --quiet --ignore-missing 2>/dev/null | grep -E 'FAILED$' || echo ' -> Sorun yok.'")

        
        disk_operations = []
        for mnt in ["/boot", "/home", "/var", "/tmp", "/opt", "/usr", "/run/shm"]:
            flags = p.get("f_" + mnt.replace("/", "_"), [])
            if flags: disk_operations.append((mnt, flags))
            
        if disk_operations:
            s.append("cp /etc/fstab /etc/fstab.bak_$(date +%s) && echo '[+] fstab yedeklendi.'")
            for mnt, flags in disk_operations:
                flag_str = "defaults," + ",".join(flags)
                safe_mnt = mnt.replace("/", "\\/")
                s.append(f"sed -i '/ {safe_mnt} / s/defaults/{flag_str}/' /etc/fstab && echo '[+] {mnt} -> {flag_str}'")

        return s if len(s) > 1 else []

    def do_POST(self):
        length = int(self.headers['Content-Length'])
        p = urllib.parse.parse_qs(self.rfile.read(length).decode())
        path = self.path

        
        script_lines = ["#!/bin/bash", "echo '[!] SISTEM SIKILASTIRMA ISLEMI BASLATILDI...'", ""]
        
        if path == "/gen_vuln":
            script_lines.extend(self.gen_vuln_script(p))
        elif path == "/gen_suid":
            script_lines.extend(self.gen_suid_script(p))
        elif path == "/gen_master":
            script_lines.extend(self.gen_master_script(p))
        elif path == "/gen_all":
            script_lines.extend(self.gen_vuln_script(p))
            script_lines.append("")
            script_lines.extend(self.gen_suid_script(p))
            script_lines.append("")
            script_lines.extend(self.gen_master_script(p))
        else:
            script_lines.append("echo 'Hata: Gecersiz islem rotasi!'")

        script_lines.append("\necho '[!] ISLEMLER TAMAMLANDI.'")
        
        res = "\\n".join(script_lines)
        html = f"""
        <html>
        <body style="background:#0a0a0c; color:#00ff41; padding:30px; font-family:monospace;">
            <h2>ÜRETİLEN BASH SCRIPT ({path})</h2>
            <div style="background:#000; padding:20px; border:1px solid #00ff41; border-radius:5px; overflow-x:auto;">
                <pre style="margin:0;">{res.replace('\\n', '<br>')}</pre>
            </div>
            <br>
            <a href="javascript:history.back()" style="color:#fff; text-decoration:none; font-weight:bold; font-size:16px; background:#222; padding:10px 20px; border-radius:5px;">&larr; Seçimlere Geri Dön (Ayarları Kaybetmeden)</a>
        </body>
        </html>
        """
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(html.encode())

socketserver.TCPServer.allow_reuse_address = True
with socketserver.TCPServer(("", PORT), UltimateHardeningHandler) as httpd:
    print(f"[+] Ultimate Hardening Suite ÇALIŞIYOR: http://localhost:{PORT}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[!] Kapatılıyor...")

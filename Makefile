# Proje Degiskenleri
PYTHON = python3
APP = ultimate_suite.py
PORT = 8080

.PHONY: help run install clean status

help:
	@echo "🛡️  Ultimate Hardening Suite - Ekip Kontrol Paneli"
	@echo "------------------------------------------------"
	@echo "Kullanim:"
	@echo "  make run      - Aracı baslatir"
	@echo "  make install  - Gerekli izinleri ayarlar (chmod)"
	@echo "  make status   - Portun ve surecin durumunu kontrol eder"
	@echo "  make clean    - Yedek dosyalarini (.bak) temizler"
	@echo "  make help     - Bu yardim mesajini gosterir"

run:
	@echo "[*] Hardening Suite $(PORT) portunda baslatiliyor..."
	$(PYTHON) $(APP)

install:
	@echo "[+] Dosya izinleri guncelleniyor..."
	chmod +x $(APP)
	@echo "[+] Gerekli paketler kontrol ediliyor..."
	sudo apt update && sudo apt install -y libpam-pwquality md5conf 2>/dev/null || echo "Paketler zaten kurulu veya manuel yukleme gerekli."

status:
	@echo "[*] Port $(PORT) durumu:"
	sudo lsof -i :$(PORT) || echo "[-] Sunucu su an calismiyor."

clean:
	@echo "[!] fstab yedekleri ve gecici dosyalar temizleniyor..."
	rm -f /etc/fstab.bak_*
	rm -f *.pyc
	@echo "[+] Temizlik tamam."
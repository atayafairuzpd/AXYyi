# PWSS VMAX 3.1 - Python Web Security Scanner

Scanner keamanan web berbasis Python yang **pasif, ramah server, dan non-intrusive**. PWSS memeriksa konfigurasi dasar (hardening) sebuah website lalu membuat skor, grade, dan laporan yang mudah dibaca.

Proyek ini berawal dari mata kuliah Teknologi Audio Visual, Institut Seni Indonesia Surakarta, dengan pertanyaan: *bagaimana jika ada scanner web yang aman dan tidak memberatkan website yang diperiksa?*

## Fitur

* 12 kelompok pemeriksaan: HTTPS/HSTS, TLS dan sertifikat, header keamanan (termasuk analisis CSP), cookie, CORS, metode HTTP, konten HTML, kebocoran informasi, bug situs (tautan rusak/error 5xx), path sensitif, WordPress, dan SPF/DMARC.
* Hanya request normal `GET`, `HEAD`, dan `OPTIONS`, dengan jeda antar request dan batas total request.
* Path sensitif diperiksa dengan `HEAD`; isi file tidak diunduh.
* Laporan `.txt`, `.json`, dan `.html`; skor 0-100 dan grade A-F.

## Instalasi

```bash
python -m pip install -r requirements.txt
```

Membutuhkan Python 3.10+. `dnspython` dipakai untuk cek SPF/DMARC (bisa dilewati dengan `--skip-dns`).

## Penggunaan

```bash
python web_security_scanner_vmax_3_1.py https://website-anda.com
python web_security_scanner_vmax_3_1.py https://website-anda.com --yes --max-pages 5 --output ./reports
python web_security_scanner_vmax_3_1.py https://website-anda.com --fail-on HIGH --no-pause   # untuk CI
```

Opsi penting: `--delay`, `--timeout`, `--max-requests` (default 80), `--max-pages`, `--max-links`, `--skip-dns`, `--skip-tls`, `--output`, `--yes`, `--fail-on`.

## Cara membaca skor

Skor = 100 dikurangi penalti per level temuan (CRITICAL 25, HIGH 15, MEDIUM 8, LOW 3, dengan batas atas per level). Grade: A >= 90, B >= 80, C >= 65, D >= 50, F < 50.

Skor hanyalah indikator, **bukan jaminan keamanan**. Perhatikan juga *confidence* dan cakupan scan di laporan. Jika target membalas 403 (misalnya karena WAF atau rate limit), hasil bisa tidak lengkap dan berbeda dari yang terlihat di browser.

## Batasan

* Bukan pentest lengkap: tidak menjalankan JavaScript, login, atau menguji logika bisnis.
* Tidak menilai versi plugin/tema atau kerentanan (CVE) spesifik.
* Hasil adalah indikasi awal, bukan bukti kerentanan yang dapat dieksploitasi; false positive dan false negative mungkin terjadi.

## Sanggahan & Batasan Tanggung Jawab (Disclaimer)

Proyek PWSS VMAX 3.1 diciptakan khusus untuk tujuan edukasi, analisis risiko dasar, serta pemindaian keamanan web yang bersifat pasif, ramah server, dan non-intrusive.

1. **Tujuan Penggunaan:** Alat ini dirancang hanya untuk dipergunakan pada sistem/website milik pribadi atau target yang telah memberikan izin resmi secara tertulis.
2. **Tanggung Jawab Modifikasi:** Pembuat utama proyek ini tidak bertanggung jawab atas segala bentuk modifikasi kode, penyalahgunaan, kerusakan server, atau tindakan ilegal yang dilakukan oleh pihak ketiga yang menggunakan atau mengembangkan ulang (fork) repositori ini.
3. **Batasan Etis:** Segala bentuk perubahan kode yang mengubah sifat dasar PWSS dari *passive scanner* menjadi *active/aggressive exploit tool* berada di luar batasan etis dan tanggung jawab pengembang asli.

Pengguna bertanggung jawab penuh atas kepatuhan terhadap hukum yang berlaku di wilayahnya. Jika Anda menemukan kerentanan pada sistem pihak lain, laporkan secara bertanggung jawab melalui kanal resmi pemilik sistem (misalnya program vulnerability disclosure), dan jangan publikasikan sebelum ditanggapi.

## Kontribusi

Lihat [CONTRIBUTING.md](CONTRIBUTING.md). Ringkasnya: kontribusi harus tetap pasif, aman, dan menjaga beban server.

## Lisensi

[MIT License](LICENSE) (c) 2026 Muhammad Ataya Fairuz Pratama. Perangkat lunak disediakan "apa adanya" tanpa garansi apa pun.

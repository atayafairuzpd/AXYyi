# Panduan Kontribusi (Contribution Guidelines)

Kami menyambut baik siapa saja yang ingin mengembangkan proyek PWSS agar menjadi lebih bermanfaat bagi komunitas. Namun, seluruh kontribusi wajib mematuhi filosofi utama PWSS:

* **Tetap Pasif & Aman:** Fitur baru tidak boleh menyertakan modul brute force, eksploitasi celah otomatis, uji login, atau eksekusi script berbahaya.
* **Menjaga Beban Server:** Setiap modul pemeriksaan wajib menerapkan batas rate-limiting dan batasan crawling agar tidak membebankan performa target.
* **Pull Request (PR) Review:** Setiap usulan fitur atau perubahan kode (Pull Request) yang melanggar prinsip keamanan pasif ini akan langsung ditolak.

## Tips sebelum mengirim PR

* Gunakan Python 3.10+ dan pastikan `python web_security_scanner_vmax_3_1.py --help` tetap berjalan.
* Uji hanya pada sistem milik sendiri atau lingkungan uji (staging/localhost). Jangan menyertakan hasil scan situs pihak lain di PR atau issue.
* Jelaskan di deskripsi PR: apa yang diperiksa, request apa yang dikirim, dan bagaimana batas request tetap terjaga.

Dengan berkontribusi, Anda setuju kontribusi Anda dilisensikan di bawah [MIT License](LICENSE).

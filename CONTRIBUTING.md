# Cara Berkontribusi

Yang paling dibutuhkan: **pemeriksaan pasif baru**. Semua harus tetap pasif, artinya cukup mengirim request biasa dan membaca respons, tanpa menyerang.

## Menambah pemeriksaan

1. Fork repo ini, buat branch baru.
2. Tambahkan logika di `src/Checks.php`. Tiap pemeriksaan mengembalikan satu atau lebih temuan lewat `$this->finding(id, judul, severity, detail, fix, evidence)`.
   - `severity`: `critical`, `high`, `medium`, `low`, `info`, atau `ok`.
   - Untuk path sensitif, tambahkan entri di `sensitiveFiles()` dengan tanda tangan isi file supaya tidak salah menandai halaman biasa.
3. Tambahkan tesnya di `tests/run.php`.
4. Jalankan `php tests/run.php`, pastikan semua lolos.
5. Kirim pull request.

## Aturan penting

- Jangan menambah apa pun yang menyerang target (brute force, injeksi payload, upload). PR seperti itu akan ditolak.
- Jangan melemahkan proteksi SSRF di `src/Http.php`.
- Jaga agar tetap tanpa dependency eksternal kalau bisa.

## Melaporkan bug atau ide

Buka issue dengan contoh situs (yang kamu punya izin) dan hasil yang kamu harapkan.

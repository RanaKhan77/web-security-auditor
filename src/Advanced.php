<?php
// Advanced passive checks used in real security audits. Still no attacks:
// header analysis, one safe OPTIONS request, DNS lookups, and reading
// same-origin scripts the page already loads.

namespace Auditor;

class Advanced
{
    public function __construct(private Http $http) {}

    /**
     * Analyse the CSP itself, not just whether it exists. A weak CSP gives a
     * false sense of safety.
     * @return array<array>
     */
    public function cspQuality(array $headers): array
    {
        $csp = $headers['content-security-policy'] ?? null;
        if (!$csp) {
            return [];
        }
        $dirs = [];
        foreach (explode(';', strtolower($csp)) as $part) {
            $tokens = preg_split('/\s+/', trim($part), -1, PREG_SPLIT_NO_EMPTY);
            if ($tokens) {
                $dirs[array_shift($tokens)] = $tokens;
            }
        }
        $scriptSrc = $dirs['script-src'] ?? $dirs['default-src'] ?? null;
        $out = [];

        if ($scriptSrc !== null && in_array("'unsafe-inline'", $scriptSrc, true)) {
            $out[] = $this->f('csp-unsafe-inline', "CSP memakai 'unsafe-inline' pada skrip", 'high',
                "Dengan 'unsafe-inline', CSP hampir tidak melindungi dari XSS karena skrip inline tetap boleh jalan.",
                "Hapus 'unsafe-inline'. Pakai nonce (script-src 'nonce-xxxx') atau hash untuk skrip yang memang perlu.",
                "Content-Security-Policy: ... " . (isset($dirs['script-src']) ? 'script-src' : 'default-src') . " ... 'unsafe-inline'");
        }
        if ($scriptSrc !== null && in_array("'unsafe-eval'", $scriptSrc, true)) {
            $out[] = $this->f('csp-unsafe-eval', "CSP memakai 'unsafe-eval'", 'medium',
                "'unsafe-eval' mengizinkan eval() dan sejenisnya, memperluas celah injeksi skrip.",
                "Hapus 'unsafe-eval' dan hindari eval(), new Function(), setTimeout(string).", '');
        }
        if ($scriptSrc !== null && array_intersect(['*', 'http:', 'https:'], $scriptSrc)) {
            $out[] = $this->f('csp-wildcard', 'CSP mengizinkan sumber skrip dari mana saja', 'high',
                'Sumber wildcard (* atau https:) membuat skrip bisa dimuat dari domain mana pun.',
                'Batasi script-src ke daftar domain tertentu atau ke \'self\'.', '');
        }
        if (!isset($dirs['object-src']) && !isset($dirs['default-src'])) {
            $out[] = $this->f('csp-object-src', "CSP tanpa object-src 'none'", 'low',
                'Tanpa object-src, plugin lawas seperti Flash/objek bisa jadi vektor serangan.',
                "Tambahkan: object-src 'none'", '');
        }
        if (!isset($dirs['base-uri'])) {
            $out[] = $this->f('csp-base-uri', 'CSP tanpa base-uri', 'low',
                'Tanpa base-uri, penyerang yang bisa menyuntik HTML dapat mengubah <base> dan membelokkan path skrip.',
                "Tambahkan: base-uri 'self'", '');
        }
        if ($scriptSrc === null) {
            $out[] = $this->f('csp-no-script', 'CSP tidak membatasi skrip', 'medium',
                'Tidak ada script-src maupun default-src, jadi CSP tidak mengatur dari mana skrip boleh dimuat.',
                "Tambahkan script-src (atau default-src) yang ketat.", '');
        }
        return $out;
    }

    /** One OPTIONS request: flag dangerous methods like TRACE (XST). */
    public function httpMethods(string $baseUrl): array
    {
        try {
            $res = $this->http->fetch($baseUrl, 'OPTIONS');
        } catch (\Throwable $e) {
            return [];
        }
        $allow = strtoupper($res['headers']['allow'] ?? '');
        if ($allow === '') {
            return [];
        }
        $out = [];
        if (str_contains($allow, 'TRACE')) {
            $out[] = $this->f('method-trace', 'Metode HTTP TRACE aktif', 'medium',
                'TRACE memungkinkan serangan Cross-Site Tracing (XST) untuk mencuri data lewat header.',
                'Matikan TRACE di server (TraceEnable Off di Apache).',
                "OPTIONS -> Allow: $allow");
        }
        $risky = array_intersect(['PUT', 'DELETE', 'PATCH'], explode(', ', $allow));
        if ($risky) {
            $out[] = $this->f('method-write', 'Metode tulis diizinkan: ' . implode(', ', $risky), 'low',
                'Metode seperti PUT/DELETE bisa berbahaya kalau tidak dibatasi autentikasi. Wajar untuk API, berisiko untuk situs biasa.',
                'Pastikan metode ini hanya untuk endpoint yang memang butuh dan sudah terproteksi.',
                "OPTIONS -> Allow: $allow");
        }
        return $out;
    }

    /** RFC 9116 security.txt: a published contact for vulnerability reports. */
    public function securityTxt(string $baseUrl): array
    {
        $base = rtrim($baseUrl, '/');
        foreach (['/.well-known/security.txt', '/security.txt'] as $path) {
            try {
                $res = $this->http->fetch($base . $path);
            } catch (\Throwable $e) {
                continue;
            }
            if ($res['status'] === 200 && stripos($res['body'], 'contact:') !== false) {
                return [$this->f('security-txt', 'security.txt tersedia', 'ok',
                    "Ada kontak untuk laporan kerentanan di $path.", '', '')];
            }
        }
        return [$this->f('security-txt-missing', 'Tidak ada security.txt', 'info',
            'security.txt (RFC 9116) memberi tahu peneliti keamanan ke mana melapor kalau menemukan celah.',
            'Buat /.well-known/security.txt berisi baris "Contact: mailto:security@domainmu".', '')];
    }

    /** Mixed content + missing Subresource Integrity, parsed from the page. */
    public function pageResources(string $scheme, string $baseUrl, string $body): array
    {
        $out = [];
        if ($scheme === 'https' && preg_match('#(?:src|href)\s*=\s*["\'](http://[^"\']+)#i', $body, $m)) {
            $out[] = $this->f('mixed-content', 'Mixed content: memuat resource lewat http', 'medium',
                'Halaman https memuat resource lewat http yang bisa disadap atau diubah di jalan.',
                'Ubah semua URL resource ke https.',
                $this->clip($m[1]));
        }
        // external scripts without integrity=
        if (preg_match_all('#<script\b[^>]*\bsrc\s*=\s*["\']([^"\']+)["\'][^>]*>#i', $body, $all, PREG_SET_ORDER)) {
            $baseHost = parse_url($baseUrl, PHP_URL_HOST);
            foreach ($all as $tag) {
                $src = $tag[1];
                $host = parse_url($src, PHP_URL_HOST);
                if ($host && $host !== $baseHost && stripos($tag[0], 'integrity=') === false) {
                    $out[] = $this->f('sri-missing', 'Skrip eksternal tanpa Subresource Integrity', 'low',
                        "Skrip dari pihak ketiga ($host) dimuat tanpa atribut integrity, jadi kalau CDN-nya dibajak, kode jahat ikut jalan.",
                        'Tambahkan atribut integrity="sha384-..." dan crossorigin pada tag <script>.',
                        $this->clip($src));
                    break; // one finding is enough to make the point
                }
            }
        }
        return $out;
    }

    /**
     * Read the same-origin JavaScript the page loads and look for leaked
     * secrets (API keys, tokens). Developers hardcode these more than you'd think.
     * @return array<array>
     */
    public function secretsInJs(string $baseUrl, string $body): array
    {
        $baseHost = parse_url($baseUrl, PHP_URL_HOST);
        $sources = [];
        if (preg_match_all('#<script\b[^>]*\bsrc\s*=\s*["\']([^"\']+)["\']#i', $body, $m)) {
            foreach ($m[1] as $src) {
                $abs = $this->absolute($baseUrl, $src);
                if ($abs && parse_url($abs, PHP_URL_HOST) === $baseHost) {
                    $sources[] = $abs;
                }
            }
        }
        $sources = array_slice(array_unique($sources), 0, 4);

        $patterns = [
            'AWS access key' => '/\bAKIA[0-9A-Z]{16}\b/',
            'Google API key' => '/\bAIza[0-9A-Za-z_\-]{35}\b/',
            'Slack token' => '/\bxox[baprs]-[0-9A-Za-z\-]{10,}/',
            'Stripe live key' => '/\bsk_live_[0-9A-Za-z]{16,}/',
            'Private key' => '/-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/',
            'Hardcoded secret' => '/["\'](?:api[_-]?key|apikey|secret|access[_-]?token|auth[_-]?token)["\']\s*[:=]\s*["\'][0-9A-Za-z_\-]{16,}["\']/i',
        ];

        $out = [];
        $texts = [['(inline)', $body]];
        foreach ($sources as $url) {
            try {
                $res = $this->http->fetch($url);
                if ($res['status'] === 200) {
                    $texts[] = [$url, $res['body']];
                }
            } catch (\Throwable $e) {
            }
        }
        foreach ($texts as [$where, $text]) {
            foreach ($patterns as $label => $re) {
                if (preg_match($re, $text, $hit)) {
                    $out[] = $this->f('secret-' . md5($label . $where), "Kemungkinan $label di JavaScript", 'high',
                        "Ditemukan pola yang mirip $label di " . ($where === '(inline)' ? 'skrip inline halaman' : $where) . ". Kredensial di kode frontend bisa dibaca siapa saja.",
                        'Pindahkan rahasia ke server. Rotasi (ganti) key yang terlanjur ada di frontend sekarang juga.',
                        $this->maskSecret($hit[0]));
                    break 2; // report the first solid hit, avoid noise
                }
            }
        }
        return $out;
    }

    /** Email spoofing protection via DNS: SPF and DMARC. Best-effort. */
    public function emailSecurity(string $host): array
    {
        if (filter_var($host, FILTER_VALIDATE_IP)) {
            return []; // email records apply to domains, not raw IPs
        }
        $domain = $this->registrableDomain($host);
        $out = [];

        $spf = null;
        foreach (@dns_get_record($domain, DNS_TXT) ?: [] as $rec) {
            if (isset($rec['txt']) && stripos($rec['txt'], 'v=spf1') === 0) {
                $spf = $rec['txt'];
            }
        }
        if ($spf === null) {
            $out[] = $this->f('spf-missing', 'Tidak ada SPF record', 'medium',
                "Tanpa SPF, orang lain lebih mudah mengirim email yang mengatasnamakan @$domain.",
                'Tambahkan TXT record SPF, mis. "v=spf1 include:_spf.google.com -all".', '');
        } elseif (preg_match('/[~?]all\b/', $spf)) {
            $out[] = $this->f('spf-soft', 'SPF tidak tegas (~all / ?all)', 'low',
                'SPF ada tapi tidak menolak pengirim palsu dengan tegas.',
                'Pakai "-all" di akhir SPF kalau daftar pengirimnya sudah pasti.',
                $this->clip($spf));
        }

        $dmarc = null;
        foreach (@dns_get_record("_dmarc.$domain", DNS_TXT) ?: [] as $rec) {
            if (isset($rec['txt']) && stripos($rec['txt'], 'v=DMARC1') === 0) {
                $dmarc = $rec['txt'];
            }
        }
        if ($dmarc === null) {
            $out[] = $this->f('dmarc-missing', 'Tidak ada DMARC record', 'medium',
                "Tanpa DMARC, penipuan email atas nama @$domain sulit dicegah dan dipantau.",
                'Tambahkan TXT _dmarc, mis. "v=DMARC1; p=quarantine; rua=mailto:dmarc@' . $domain . '".', '');
        } elseif (preg_match('/p\s*=\s*none/i', $dmarc)) {
            $out[] = $this->f('dmarc-none', 'DMARC hanya memantau (p=none)', 'low',
                'DMARC ada tapi tidak menolak email palsu, hanya memantau.',
                'Naikkan ke p=quarantine lalu p=reject setelah yakin aman.',
                $this->clip($dmarc));
        }
        return $out;
    }

    // --- helpers ---

    private function f(string $id, string $title, string $severity, string $detail, string $fix, string $evidence = ''): array
    {
        return compact('id', 'title', 'severity', 'detail', 'fix', 'evidence');
    }

    private function absolute(string $base, string $href): ?string
    {
        $href = trim($href);
        if ($href === '' || str_starts_with($href, 'data:')) {
            return null;
        }
        if (preg_match('#^https?://#i', $href)) {
            return $href;
        }
        $b = parse_url($base);
        $origin = $b['scheme'] . '://' . $b['host'] . (isset($b['port']) ? ':' . $b['port'] : '');
        if (str_starts_with($href, '//')) {
            return $b['scheme'] . ':' . $href;
        }
        return str_starts_with($href, '/') ? $origin . $href : $origin . '/' . ltrim($href, './');
    }

    private function registrableDomain(string $host): string
    {
        $parts = explode('.', $host);
        $multi = ['co.id', 'or.id', 'ac.id', 'go.id', 'web.id', 'my.id', 'co.uk', 'com.au'];
        if (count($parts) > 2 && in_array(implode('.', array_slice($parts, -2)), $multi, true)) {
            return implode('.', array_slice($parts, -3));
        }
        return count($parts) > 2 ? implode('.', array_slice($parts, -2)) : $host;
    }

    private function maskSecret(string $s): string
    {
        $s = trim($s);
        if (strlen($s) <= 10) {
            return substr($s, 0, 3) . '***';
        }
        return substr($s, 0, 6) . str_repeat('*', 6) . substr($s, -4);
    }

    private function clip(string $s): string
    {
        $s = trim($s);
        return strlen($s) > 160 ? substr($s, 0, 160) . ' ...' : $s;
    }
}

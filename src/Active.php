<?php
// ACTIVE checks. These send test payloads, so they only run when the operator
// explicitly turns active mode on (AUDITOR_ACTIVE=1) AND the user confirms
// authorization for this scan. Payloads are detection-only, never destructive:
// a unique marker to spot reflection, a single quote to surface DB errors,
// and a benign canary URL to spot open redirects. No data is modified or stolen.

namespace Auditor;

class Active
{
    private const COMMON_PARAMS = ['q', 's', 'search', 'query', 'id', 'page', 'name', 'cat', 'p', 'lang', 'keyword'];
    private const REDIRECT_PARAMS = ['url', 'next', 'redirect', 'redirect_uri', 'return', 'returnurl', 'return_to', 'dest', 'destination', 'continue', 'r', 'u', 'go', 'out', 'link'];
    private const MAX_PARAMS = 10;

    // DB error signatures that indicate a query broke on our single quote.
    private const SQL_ERRORS = [
        '/SQL syntax.*MySQL/i', '/Warning.*mysqli?_/i', '/MySqlException/i',
        '/PostgreSQL.*ERROR/i', '/pg_query\(\)/i', '/ORA-\d{5}/',
        '/Microsoft OLE DB Provider for SQL Server/i', '/Unclosed quotation mark after the character string/i',
        '/SQLite3?::query/i', '/SQLSTATE\[/i', '/supplied argument is not a valid MySQL/i',
    ];

    public function __construct(private Http $http) {}

    /** @return array<array> */
    public function run(string $baseUrl, string $body): array
    {
        $params = $this->discoverParams($baseUrl, $body);
        return array_merge(
            $this->reflectedXss($baseUrl, $params),
            $this->sqlInjection($baseUrl, $params),
            $this->openRedirect($baseUrl, $params),
        );
    }

    /** Unique marker with special chars; if it comes back unencoded, output isn't escaped. */
    private function reflectedXss(string $baseUrl, array $params): array
    {
        $token = 'xP' . bin2hex(random_bytes(4));
        $probe = $token . '"\'<svg/onx>'; // benign marker, no working script
        $out = [];
        foreach ($params as $p) {
            $res = $this->request($baseUrl, $p, $probe);
            if ($res === null) {
                continue;
            }
            $ct = $res['headers']['content-type'] ?? '';
            if (stripos($ct, 'html') === false && $ct !== '') {
                continue; // reflection only matters when rendered as HTML
            }
            if (str_contains($res['body'], $token . '"\'<svg/onx>')) {
                $out[] = $this->f("xss-$p", "Kemungkinan reflected XSS lewat parameter \"$p\"", 'high',
                    "Nilai parameter \"$p\" dipantulkan ke halaman tanpa di-escape, termasuk karakter < > \" '. Penyerang bisa menyisipkan skrip lewat parameter ini.",
                    "Escape semua output sesuai konteks (htmlspecialchars untuk HTML), dan terapkan Content-Security-Policy yang ketat.",
                    "GET ?$p=$probe\n-> dipantulkan mentah di body HTML");
                break; // one solid proof is enough
            }
        }
        return $out;
    }

    /** A single quote that triggers a database error reveals an injection point. */
    private function sqlInjection(string $baseUrl, array $params): array
    {
        $out = [];
        foreach ($params as $p) {
            $res = $this->request($baseUrl, $p, "1'");
            if ($res === null) {
                continue;
            }
            foreach (self::SQL_ERRORS as $re) {
                if (preg_match($re, $res['body'], $m)) {
                    $out[] = $this->f("sqli-$p", "Kemungkinan SQL injection lewat parameter \"$p\"", 'critical',
                        "Menambahkan satu petik ke parameter \"$p\" memunculkan pesan error database. Ini tanda input masuk langsung ke query SQL.",
                        "Pakai prepared statement (parameterized query), jangan menyambung string ke SQL. Matikan tampilan error database ke publik.",
                        "GET ?$p=1'\n-> " . $this->clip($m[0]));
                    break 2;
                }
            }
        }
        return $out;
    }

    /** A benign external canary in a redirect param; if the server sends us there, it's an open redirect. */
    private function openRedirect(string $baseUrl, array $params): array
    {
        $canaryHost = 'redirect-probe.example.org';
        $canary = "https://$canaryHost/";
        $targets = array_values(array_intersect($params, self::REDIRECT_PARAMS)) ?: ['next', 'url', 'redirect'];
        $out = [];
        foreach (array_slice($targets, 0, 6) as $p) {
            $url = $this->withParam($baseUrl, $p, $canary);
            try {
                $res = $this->http->fetch($url, 'GET', [], false); // do NOT follow the redirect
            } catch (\Throwable $e) {
                continue;
            }
            $loc = $res['headers']['location'] ?? '';
            if ($res['status'] >= 300 && $res['status'] < 400 && stripos(parse_url($loc, PHP_URL_HOST) ?? '', $canaryHost) !== false) {
                $out[] = $this->f("openredir-$p", "Open redirect lewat parameter \"$p\"", 'medium',
                    "Parameter \"$p\" mengarahkan pengunjung ke URL luar mana pun. Ini dipakai untuk phishing: link terlihat dari domainmu tapi melempar ke situs penipu.",
                    "Jangan redirect ke URL dari input mentah. Pakai daftar putih tujuan, atau hanya izinkan path relatif.",
                    "GET ?$p=$canary\n-> Location: " . $this->clip($loc));
                break;
            }
        }
        return $out;
    }

    // --- helpers ---

    private function discoverParams(string $baseUrl, string $body): array
    {
        $params = [];
        // params already present on same-origin links
        if (preg_match_all('/[?&]([a-z0-9_\-]{1,30})=/i', $body, $m)) {
            $params = array_merge($params, $m[1]);
        }
        // form input names
        if (preg_match_all('/<(?:input|select|textarea)\b[^>]*\bname\s*=\s*["\']?([a-z0-9_\-]{1,30})/i', $body, $m)) {
            $params = array_merge($params, $m[1]);
        }
        $params = array_merge($params, self::COMMON_PARAMS, self::REDIRECT_PARAMS);
        $params = array_values(array_unique(array_map('strtolower', $params)));
        return array_slice($params, 0, self::MAX_PARAMS);
    }

    private function request(string $baseUrl, string $param, string $value): ?array
    {
        try {
            return $this->http->fetch($this->withParam($baseUrl, $param, $value));
        } catch (\Throwable $e) {
            return null;
        }
    }

    private function withParam(string $url, string $param, string $value): string
    {
        $sep = str_contains($url, '?') ? '&' : '?';
        return $url . $sep . rawurlencode($param) . '=' . rawurlencode($value);
    }

    private function f(string $id, string $title, string $severity, string $detail, string $fix, string $evidence): array
    {
        return compact('id', 'title', 'severity', 'detail', 'fix', 'evidence');
    }

    private function clip(string $s): string
    {
        $s = trim(preg_replace('/\s+/', ' ', $s));
        return strlen($s) > 180 ? substr($s, 0, 180) . ' ...' : $s;
    }
}

<?php
// Safe HTTP client for passive scanning.
// Guards against SSRF: only http/https, only public IPs, pinned resolution,
// manual redirect handling with re-validation on every hop.

namespace Auditor;

class SsrfException extends \RuntimeException {}

class Http
{
    const USER_AGENT = 'CyberShield-Audit/1.0 (+https://github.com/bramcps/web-security-auditor; passive scanner)';
    const TIMEOUT = 12;
    const MAX_REDIRECTS = 4;
    const MAX_BODY = 512000; // 500 KB is plenty for header/signature checks

    /** @var array<string,string> host -> pinned public IP, reused across a scan */
    private array $pinned = [];

    // Allow private/loopback targets. Only ever set by the CLI/tests for local
    // fixtures. The web endpoint (api/scan.php) never enables this.
    private bool $allowPrivate;

    public function __construct(bool $allowPrivate = false)
    {
        $this->allowPrivate = $allowPrivate;
    }

    /**
     * Fetch a URL safely. Returns [status, headers (lower-cased keys), body, finalUrl, ip].
     * @param array<string,string> $extraHeaders
     */
    public function fetch(string $url, string $method = 'GET', array $extraHeaders = []): array
    {
        $redirects = 0;
        while (true) {
            $ip = $this->resolvePublicIp($url);
            $result = $this->request($url, $ip, $method, $extraHeaders);

            if ($result['status'] >= 300 && $result['status'] < 400 && isset($result['headers']['location']) && $redirects < self::MAX_REDIRECTS) {
                $url = $this->absoluteUrl($url, $result['headers']['location']);
                $redirects++;
                $method = 'GET';
                continue;
            }
            $result['finalUrl'] = $url;
            $result['ip'] = $ip;
            return $result;
        }
    }

    private function request(string $url, string $ip, string $method, array $extraHeaders): array
    {
        // Prefer curl; fall back to PHP streams when the curl extension isn't loaded.
        if (function_exists('curl_init') && getenv('AUDITOR_FORCE_STREAMS') !== '1') {
            return $this->requestCurl($url, $ip, $method, $extraHeaders);
        }
        return $this->requestStreams($url, $ip, $method, $extraHeaders);
    }

    private function requestCurl(string $url, string $ip, string $method, array $extraHeaders): array
    {
        $parts = parse_url($url);
        $host = $parts['host'];
        $port = $parts['port'] ?? ($parts['scheme'] === 'https' ? 443 : 80);

        $ch = curl_init();
        $headerLines = [];
        curl_setopt_array($ch, [
            CURLOPT_URL => $url,
            CURLOPT_CUSTOMREQUEST => $method,
            CURLOPT_NOBODY => $method === 'HEAD',
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_CONNECTTIMEOUT => self::TIMEOUT,
            CURLOPT_TIMEOUT => self::TIMEOUT,
            CURLOPT_SSL_VERIFYPEER => false, // we report TLS issues, never block on them
            CURLOPT_SSL_VERIFYHOST => 0,
            CURLOPT_USERAGENT => self::USER_AGENT,
            CURLOPT_RESOLVE => ["$host:$port:$ip"], // pin to the validated IP (anti DNS-rebinding)
            CURLOPT_HTTPHEADER => $this->formatHeaders($extraHeaders),
            CURLOPT_ACCEPT_ENCODING => '',
            CURLOPT_HEADERFUNCTION => function ($ch, $line) use (&$headerLines) {
                $headerLines[] = $line;
                return strlen($line);
            },
            CURLOPT_BUFFERSIZE => 16384,
            CURLOPT_NOPROGRESS => false,
            CURLOPT_PROGRESSFUNCTION => function ($ch, $dlTotal, $dlNow) {
                return $dlNow > self::MAX_BODY ? 1 : 0; // abort oversized bodies
            },
        ]);

        $body = curl_exec($ch);
        $errno = curl_errno($ch);
        $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        curl_close($ch);

        if ($errno && $errno !== CURLE_ABORTED_BY_CALLBACK) {
            throw new \RuntimeException('Request gagal: ' . curl_strerror($errno));
        }

        return [
            'status' => $status,
            'headers' => $this->parseHeaders($headerLines),
            'rawHeaders' => $headerLines,
            'body' => (string) $body,
        ];
    }

    /** Fallback client using PHP streams, for hosts without the curl extension. */
    private function requestStreams(string $url, string $ip, string $method, array $extraHeaders): array
    {
        $parts = parse_url($url);
        $host = $parts['host'];

        $headers = ["Host: $host", 'User-Agent: ' . self::USER_AGENT, 'Accept: */*', 'Connection: close'];
        foreach ($extraHeaders as $k => $v) {
            $headers[] = "$k: $v";
        }

        $context = stream_context_create([
            'http' => [
                'method' => $method,
                'header' => implode("\r\n", $headers),
                'protocol_version' => '1.1',
                'follow_location' => 0,
                'ignore_errors' => true, // read the body even on 4xx/5xx
                'timeout' => self::TIMEOUT,
            ],
            'ssl' => [
                'verify_peer' => false,
                'verify_peer_name' => false,
                'SNI_enabled' => true,
                'peer_name' => $host,
            ],
        ]);

        if (($parts['scheme'] ?? '') === 'https' && !extension_loaded('openssl')) {
            throw new \RuntimeException(
                'Untuk memindai situs https, aktifkan ekstensi PHP "openssl" (dan sebaiknya "curl") di php.ini, lalu jalankan ulang server. Lihat README bagian "Cara pakai".'
            );
        }

        $lastError = '';
        set_error_handler(function ($n, $m) use (&$lastError) { $lastError = $m; return true; });
        $stream = fopen($url, 'r', false, $context);
        if ($stream === false) {
            restore_error_handler();
            throw new \RuntimeException('Request gagal: tidak bisa membuka koneksi ke ' . $host .
                ($lastError ? ' (' . preg_replace('#^fopen\([^)]*\):\s*#', '', $lastError) . ')' : ''));
        }
        $meta = stream_get_meta_data($stream);
        $responseHeaders = $meta['wrapper_data'] ?? [];
        $body = stream_get_contents($stream, self::MAX_BODY);
        fclose($stream);
        restore_error_handler();

        $status = 0;
        foreach ($responseHeaders as $line) {
            if (preg_match('#^HTTP/\S+\s+(\d{3})#', $line, $m)) {
                $status = (int) $m[1]; // last status line wins (handles 100-continue)
            }
        }

        return [
            'status' => $status,
            'headers' => $this->parseHeaders($responseHeaders),
            'rawHeaders' => $responseHeaders,
            'body' => (string) $body,
        ];
    }

    /** Resolve a host and return a single public IP, or throw if it points anywhere private. */
    private function resolvePublicIp(string $url): string
    {
        $parts = parse_url($url);
        if ($parts === false || !isset($parts['scheme'], $parts['host'])) {
            throw new SsrfException('URL tidak valid.');
        }
        if (!in_array(strtolower($parts['scheme']), ['http', 'https'], true)) {
            throw new SsrfException('Hanya alamat http dan https yang diperbolehkan.');
        }
        $host = $parts['host'];
        if (isset($this->pinned[$host])) {
            return $this->pinned[$host];
        }

        if (filter_var($host, FILTER_VALIDATE_IP)) {
            $ips = [$host];
        } else {
            $ips = @gethostbynamel($host) ?: [];
            foreach (@dns_get_record($host, DNS_AAAA) ?: [] as $rec) {
                if (!empty($rec['ipv6'])) {
                    $ips[] = $rec['ipv6'];
                }
            }
        }
        $ips = array_values(array_filter(array_unique($ips)));
        if (!$ips) {
            throw new SsrfException("Nama domain tidak bisa di-resolve: $host");
        }
        foreach ($ips as $ip) {
            if (!$this->allowPrivate && !$this->isPublicIp($ip)) {
                throw new SsrfException("Target menunjuk ke alamat internal ($ip). Pemindaian dibatalkan demi keamanan.");
            }
        }
        return $this->pinned[$host] = $ips[0];
    }

    private function isPublicIp(string $ip): bool
    {
        return (bool) filter_var(
            $ip,
            FILTER_VALIDATE_IP,
            FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
        );
    }

    private function absoluteUrl(string $base, string $location): string
    {
        if (preg_match('#^https?://#i', $location)) {
            return $location;
        }
        $b = parse_url($base);
        $scheme = $b['scheme'] ?? 'https';
        $host = $b['host'] ?? '';
        $port = isset($b['port']) ? ':' . $b['port'] : '';
        if (str_starts_with($location, '//')) {
            return "$scheme:$location";
        }
        if (str_starts_with($location, '/')) {
            return "$scheme://$host$port$location";
        }
        $path = $b['path'] ?? '/';
        $dir = substr($path, 0, strrpos($path, '/') + 1);
        return "$scheme://$host$port$dir$location";
    }

    /** @param array<string,string> $headers */
    private function formatHeaders(array $headers): array
    {
        $out = [];
        foreach ($headers as $k => $v) {
            $out[] = "$k: $v";
        }
        return $out;
    }

    /** @param string[] $lines @return array<string,string> last value per lower-cased name */
    private function parseHeaders(array $lines): array
    {
        $headers = [];
        foreach ($lines as $line) {
            $line = trim($line);
            if ($line === '' || stripos($line, 'HTTP/') === 0) {
                continue;
            }
            $pos = strpos($line, ':');
            if ($pos === false) {
                continue;
            }
            $name = strtolower(trim(substr($line, 0, $pos)));
            $value = trim(substr($line, $pos + 1));
            // keep set-cookie as a list, everything else last-wins
            if ($name === 'set-cookie') {
                $headers['set-cookie'] = $headers['set-cookie'] ?? [];
                $headers['set-cookie'][] = $value;
            } else {
                $headers[$name] = $value;
            }
        }
        return $headers;
    }
}

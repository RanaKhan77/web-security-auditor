<?php
namespace Auditor;

require_once __DIR__ . '/Http.php';
require_once __DIR__ . '/Tls.php';
require_once __DIR__ . '/Checks.php';
require_once __DIR__ . '/Grade.php';

class Scanner
{
    private Http $http;
    private Checks $checks;
    private Tls $tls;

    public function __construct(bool $allowPrivate = false)
    {
        $this->http = new Http($allowPrivate);
        $this->checks = new Checks($this->http);
        $this->tls = new Tls();
    }

    /** Normalise user input into a scannable base URL, or throw. */
    public static function normalizeUrl(string $input): string
    {
        $input = trim($input);
        if ($input === '') {
            throw new \InvalidArgumentException('Masukkan alamat situs.');
        }
        if (!preg_match('#^https?://#i', $input)) {
            $input = 'https://' . $input;
        }
        $parts = parse_url($input);
        if ($parts === false || empty($parts['host']) || !str_contains($parts['host'], '.')) {
            throw new \InvalidArgumentException('Alamat situs tidak valid.');
        }
        $scheme = strtolower($parts['scheme']);
        $host = $parts['host'];
        $port = isset($parts['port']) ? ':' . $parts['port'] : '';
        return "$scheme://$host$port" . ($parts['path'] ?? '');
    }

    /** @return array full report */
    public function scan(string $input): array
    {
        $url = self::normalizeUrl($input);
        $started = microtime(true);

        $landing = $this->http->fetch($url);
        $scheme = parse_url($landing['finalUrl'], PHP_URL_SCHEME);
        $host = parse_url($landing['finalUrl'], PHP_URL_HOST);

        $tlsInfo = $scheme === 'https'
            ? $this->tls->inspect($host, $landing['ip'], parse_url($landing['finalUrl'], PHP_URL_PORT) ?: 443)
            : ['ok' => false, 'error' => 'bukan https'];

        $findings = array_merge(
            $this->checks->tls($scheme, $tlsInfo),
            $this->checks->securityHeaders($landing['headers']),
            $this->checks->cookies($landing['headers']),
            $this->checks->infoDisclosure($landing['headers'], $landing['body']),
            $this->checks->sensitiveFiles($landing['finalUrl']),
            $this->checks->discovery($landing['finalUrl'], $landing['body']),
            $this->checks->cors($landing['finalUrl']),
        );

        $grade = Grade::fromFindings($findings);

        return [
            'target' => [
                'input' => $input,
                'final_url' => $landing['finalUrl'],
                'host' => $host,
                'ip' => $landing['ip'],
                'status' => $landing['status'],
                'scheme' => $scheme,
            ],
            'grade' => $grade,
            'summary' => $this->summarize($findings),
            'findings' => $findings,
            'scanned_at' => gmdate('c'),
            'duration_ms' => (int) round((microtime(true) - $started) * 1000),
        ];
    }

    private function summarize(array $findings): array
    {
        $counts = ['critical' => 0, 'high' => 0, 'medium' => 0, 'low' => 0, 'info' => 0, 'ok' => 0];
        foreach ($findings as $f) {
            $counts[$f['severity']] = ($counts[$f['severity']] ?? 0) + 1;
        }
        return $counts;
    }
}

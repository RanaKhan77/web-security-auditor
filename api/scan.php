<?php
// JSON endpoint: POST { "url": "...", "consent": true } -> full report.
// Keeps a short per-IP rate limit so the tool can't be used to hammer a target.

require_once __DIR__ . '/../src/Scanner.php';

use Auditor\Scanner;
use Auditor\SsrfException;

// Never let a PHP notice/warning leak into the JSON body and corrupt it.
ini_set('display_errors', '0');
ini_set('html_errors', '0');
error_reporting(E_ALL);
ob_start();

// If a fatal error ends the request, still return JSON (never an empty body).
register_shutdown_function(function () {
    $e = error_get_last();
    if ($e && in_array($e['type'], [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR, E_RECOVERABLE_ERROR], true)) {
        if (ob_get_level() > 0) {
            ob_end_clean();
        }
        if (!headers_sent()) {
            http_response_code(500);
            header('Content-Type: application/json; charset=utf-8');
        }
        $msg = 'Terjadi kesalahan internal saat memindai. Coba situs lain atau laporkan di GitHub.';
        if (getenv('AUDITOR_DEBUG') === '1') {
            $msg .= ' [debug] ' . $e['message'] . ' @ ' . basename($e['file']) . ':' . $e['line'];
        }
        echo json_encode(['error' => $msg]);
    }
});

header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');

function respond(int $code, array $body): never
{
    if (ob_get_level() > 0) {
        ob_end_clean(); // drop any stray warning output before sending JSON
    }
    http_response_code($code);
    echo json_encode($body, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    exit;
}

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') {
    respond(405, ['error' => 'Gunakan metode POST.']);
}

$raw = file_get_contents('php://input');
$data = json_decode($raw, true);
if (!is_array($data)) {
    parse_str($raw, $data); // allow form posts too
}

$url = trim((string) ($data['url'] ?? ''));
$consent = filter_var($data['consent'] ?? false, FILTER_VALIDATE_BOOL);
$activeRequested = filter_var($data['active'] ?? false, FILTER_VALIDATE_BOOL);

if ($url === '') {
    respond(400, ['error' => 'Masukkan alamat situs.']);
}
if (!$consent) {
    respond(400, ['error' => 'Kamu harus menyatakan bahwa situs ini milikmu atau kamu punya izin untuk memindainya.']);
}

// Active mode (sends test payloads) is double-gated: the operator must enable it
// on the server, AND the user must opt in for this scan. Off everywhere else.
$activeMode = $activeRequested && getenv('AUDITOR_ACTIVE') === '1';
if ($activeRequested && getenv('AUDITOR_ACTIVE') !== '1') {
    respond(400, ['error' => 'Mode aktif tidak diaktifkan di server ini. Jalankan server dengan AUDITOR_ACTIVE=1 untuk mengizinkannya (hanya untuk target yang kamu punya izin).']);
}

// Simple rate limit: 10 scans per IP per 10 minutes.
$ip = $_SERVER['REMOTE_ADDR'] ?? 'cli';
$bucket = sys_get_temp_dir() . '/wsa_rl_' . md5($ip);
$now = time();
$hits = array_filter(
    is_file($bucket) ? (json_decode(file_get_contents($bucket), true) ?: []) : [],
    fn($t) => $t > $now - 600
);
if (count($hits) >= 10) {
    respond(429, ['error' => 'Terlalu banyak pemindaian. Coba lagi beberapa menit lagi.']);
}
$hits[] = $now;
@file_put_contents($bucket, json_encode(array_values($hits)));

// Local-dev escape hatch for scanning private targets (e.g. a test fixture on
// localhost). Off by default. NEVER set AUDITOR_ALLOW_PRIVATE=1 on a public
// deployment: it turns the scanner into an SSRF tool against your own network.
$allowPrivate = getenv('AUDITOR_ALLOW_PRIVATE') === '1';

// A thorough scan makes many sequential requests; give it room past the
// default 30s cap that some PHP setups (e.g. Windows) apply to the dev server.
@set_time_limit(120);

try {
    $report = (new Scanner($allowPrivate, $activeMode))->scan($url);
    respond(200, $report);
} catch (SsrfException $e) {
    respond(422, ['error' => $e->getMessage()]);
} catch (InvalidArgumentException $e) {
    respond(400, ['error' => $e->getMessage()]);
} catch (Throwable $e) {
    $detail = $e->getMessage();
    if (getenv('AUDITOR_DEBUG') === '1') {
        $detail .= ' @ ' . basename($e->getFile()) . ':' . $e->getLine();
    }
    respond(502, ['error' => 'Gagal memindai situs: ' . $detail]);
}

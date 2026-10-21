<?php
// Router for the built-in PHP server: `php -S localhost:8000 router.php`
// Serves the static UI from public/ and routes /api/scan to the endpoint.

$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);

if ($path === '/api/scan') {
    require __DIR__ . '/api/scan.php';
    return true;
}

$file = realpath(__DIR__ . '/public' . ($path === '/' ? '/index.html' : $path));
$root = realpath(__DIR__ . '/public');

if ($file && $root && str_starts_with($file, $root) && is_file($file)) {
    $types = [
        'html' => 'text/html; charset=utf-8',
        'css' => 'text/css; charset=utf-8',
        'js' => 'application/javascript; charset=utf-8',
        'svg' => 'image/svg+xml',
        'png' => 'image/png',
        'ico' => 'image/x-icon',
    ];
    $ext = strtolower(pathinfo($file, PATHINFO_EXTENSION));
    header('Content-Type: ' . ($types[$ext] ?? 'application/octet-stream'));
    readfile($file);
    return true;
}

http_response_code(404);
echo 'Not found';
return true;

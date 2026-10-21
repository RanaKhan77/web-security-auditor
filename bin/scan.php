<?php
// CLI runner: php bin/scan.php example.com
require_once __DIR__ . '/../src/Scanner.php';

$args = array_slice($argv, 1);
$allowPrivate = in_array('--allow-private', $args, true); // local testing only
$target = implode('', array_filter($args, fn($a) => !str_starts_with($a, '--')));
if ($target === '') {
    fwrite(STDERR, "Pakai: php bin/scan.php <url>\n");
    exit(1);
}

try {
    $report = (new Auditor\Scanner($allowPrivate))->scan($target);
} catch (\Throwable $e) {
    fwrite(STDERR, 'Error: ' . $e->getMessage() . "\n");
    exit(1);
}

$g = $report['grade'];
echo "\n  {$report['target']['final_url']}\n";
echo "  Nilai: {$g['letter']} ({$g['score']}/100) - {$g['label']}\n\n";

$icons = ['critical' => '[!!]', 'high' => '[! ]', 'medium' => '[~ ]', 'low' => '[. ]', 'info' => '[i ]', 'ok' => '[ok]'];
foreach ($report['findings'] as $f) {
    if ($f['severity'] === 'ok') {
        continue;
    }
    echo "  {$icons[$f['severity']]} {$f['title']}\n";
}
echo "\n  Selesai dalam {$report['duration_ms']} ms\n";

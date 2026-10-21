<?php
namespace Auditor;

class Grade
{
    private const PENALTY = [
        'critical' => 40,
        'high' => 20,
        'medium' => 8,
        'low' => 3,
        'info' => 0,
        'ok' => 0,
    ];

    /** @return array{score:int,letter:string,label:string} */
    public static function fromFindings(array $findings): array
    {
        $score = 100;
        foreach ($findings as $f) {
            $score -= self::PENALTY[$f['severity']] ?? 0;
        }
        $score = max(0, min(100, $score));

        [$letter, $label] = match (true) {
            $score >= 90 => ['A', 'Sangat baik'],
            $score >= 75 => ['B', 'Baik, ada yang bisa dirapikan'],
            $score >= 60 => ['C', 'Cukup, beberapa hal perlu diperbaiki'],
            $score >= 40 => ['D', 'Lemah, segera perbaiki'],
            default => ['F', 'Berisiko tinggi'],
        };

        return ['score' => $score, 'letter' => $letter, 'label' => $label];
    }
}

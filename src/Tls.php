<?php
// Reads the TLS certificate and negotiated protocol for a host, without sending
// any application data. Pure inspection.

namespace Auditor;

class Tls
{
    /**
     * @return array{ok:bool,error?:string,protocol?:string,valid_from?:int,valid_to?:int,days_left?:int,issuer?:string,self_signed?:bool,san?:string[]}
     */
    public function inspect(string $host, string $pinnedIp, int $port = 443): array
    {
        $context = stream_context_create(['ssl' => [
            'capture_peer_cert' => true,
            'verify_peer' => false,
            'verify_peer_name' => false,
            'SNI_enabled' => true,
            'peer_name' => $host,
        ]]);

        $errno = 0;
        $errstr = '';
        // connect to the already-validated public IP, carry SNI via peer_name
        $client = @stream_socket_client(
            "ssl://$pinnedIp:$port",
            $errno,
            $errstr,
            Http::TIMEOUT,
            STREAM_CLIENT_CONNECT,
            $context
        );

        if (!$client) {
            return ['ok' => false, 'error' => $errstr ?: 'Tidak bisa membuka koneksi TLS'];
        }

        $params = stream_context_get_params($client);
        $meta = stream_get_meta_data($client);
        fclose($client);

        $protocol = $meta['crypto']['protocol'] ?? ($this->guessProtocol($meta));
        $certResource = $params['options']['ssl']['peer_certificate'] ?? null;
        if (!$certResource) {
            return ['ok' => true, 'protocol' => $protocol];
        }

        $cert = openssl_x509_parse($certResource);
        $issuer = $cert['issuer']['O'] ?? ($cert['issuer']['CN'] ?? 'tidak diketahui');
        $subjectCn = $cert['subject']['CN'] ?? '';
        $san = [];
        if (!empty($cert['extensions']['subjectAltName'])) {
            foreach (explode(',', $cert['extensions']['subjectAltName']) as $entry) {
                $entry = trim($entry);
                if (str_starts_with($entry, 'DNS:')) {
                    $san[] = substr($entry, 4);
                }
            }
        }

        return [
            'ok' => true,
            'protocol' => $protocol,
            'valid_from' => $cert['validFrom_time_t'] ?? null,
            'valid_to' => $cert['validTo_time_t'] ?? null,
            'days_left' => isset($cert['validTo_time_t']) ? (int) floor(($cert['validTo_time_t'] - time()) / 86400) : null,
            'issuer' => $issuer,
            'self_signed' => ($cert['issuer'] ?? null) === ($cert['subject'] ?? null),
            'san' => $san,
        ];
    }

    private function guessProtocol(array $meta): string
    {
        return $meta['crypto']['protocol'] ?? 'TLS';
    }
}

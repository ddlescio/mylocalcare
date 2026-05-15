<?php
declare(strict_types=1);

/*
|--------------------------------------------------------------------------
| MyLocalCare - Mail API Aruba
|--------------------------------------------------------------------------
| Endpoint HTTP interno chiamato da Flask/Render per inviare email
| dal server Aruba usando mail().
|
| Metodo: POST
| Content-Type atteso: application/json
|--------------------------------------------------------------------------
*/

header('Content-Type: application/json; charset=utf-8');

// ======================================================
// CONFIGURAZIONE
// ======================================================

// CAMBIA QUESTA STRINGA con un secret lungo e casuale.
// Dovrà essere identico anche su Render come variabile MAILAPI_SECRET.
const MAILAPI_SECRET = 'LC_MAILAPI_2026_STRINGA_LUNGA_CASUALE_DA_NON_CONDIVIDERE_MYLOCALCARE2026';

const FROM_EMAIL = 'info@mylocalcare.it';
const FROM_NAME  = 'MyLocalCare';
const REPLY_TO   = 'info@mylocalcare.it';

// ======================================================
// FUNZIONI DI SUPPORTO
// ======================================================

function json_response(bool $ok, array $data = [], int $status = 200): void
{
    http_response_code($status);
    echo json_encode(
        array_merge(['ok' => $ok], $data),
        JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES
    );
    exit;
}

function clean_header_value(string $value): string
{
    // Evita header injection
    return trim(str_replace(["\r", "\n"], '', $value));
}

function get_client_ip(): string
{
    return $_SERVER['REMOTE_ADDR'] ?? '';
}

// ======================================================
// CONTROLLO METODO
// ======================================================

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    json_response(false, [
        'error' => 'method_not_allowed',
        'message' => 'Usare metodo POST.'
    ], 405);
}

// ======================================================
// LETTURA JSON
// ======================================================

$raw = file_get_contents('php://input');

if (!$raw) {
    json_response(false, [
        'error' => 'empty_body',
        'message' => 'Body JSON mancante.'
    ], 400);
}

$data = json_decode($raw, true);

if (!is_array($data)) {
    json_response(false, [
        'error' => 'invalid_json',
        'message' => 'JSON non valido.'
    ], 400);
}

// ======================================================
// AUTENTICAZIONE
// ======================================================

$secret = isset($data['secret']) ? (string)$data['secret'] : '';

if (!hash_equals(MAILAPI_SECRET, $secret)) {
    json_response(false, [
        'error' => 'unauthorized',
        'message' => 'Secret non valido.'
    ], 403);
}

// ======================================================
// VALIDAZIONE CAMPI
// ======================================================

$to      = isset($data['to']) ? trim((string)$data['to']) : '';
$subject = isset($data['subject']) ? clean_header_value((string)$data['subject']) : '';
$html    = isset($data['html']) ? (string)$data['html'] : '';
$text    = isset($data['text']) ? (string)$data['text'] : '';

if (!filter_var($to, FILTER_VALIDATE_EMAIL)) {
    json_response(false, [
        'error' => 'invalid_to',
        'message' => 'Destinatario non valido.'
    ], 400);
}

if ($subject === '') {
    json_response(false, [
        'error' => 'missing_subject',
        'message' => 'Oggetto mancante.'
    ], 400);
}

if ($html === '' && $text === '') {
    json_response(false, [
        'error' => 'missing_body',
        'message' => 'Corpo email mancante.'
    ], 400);
}

if ($html === '') {
    $html = nl2br(htmlspecialchars($text, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'));
}

if ($text === '') {
    $text = strip_tags(str_replace(['<br>', '<br/>', '<br />'], "\n", $html));
}

// ======================================================
// COSTRUZIONE EMAIL MULTIPART
// ======================================================

$boundary = '=_MyLocalCare_' . bin2hex(random_bytes(16));

$encodedFromName = '=?UTF-8?B?' . base64_encode(FROM_NAME) . '?=';

$headers = [];
$headers[] = 'From: ' . $encodedFromName . ' <' . FROM_EMAIL . '>';
$headers[] = 'Reply-To: ' . REPLY_TO;
$headers[] = 'MIME-Version: 1.0';
$headers[] = 'Content-Type: multipart/alternative; boundary="' . $boundary . '"';
$headers[] = 'X-Mailer: MyLocalCare MailAPI Aruba';
$headers[] = 'X-LocalCare-MailAPI: aruba-php';

$message  = "--{$boundary}\r\n";
$message .= "Content-Type: text/plain; charset=UTF-8\r\n";
$message .= "Content-Transfer-Encoding: 8bit\r\n\r\n";
$message .= $text . "\r\n\r\n";

$message .= "--{$boundary}\r\n";
$message .= "Content-Type: text/html; charset=UTF-8\r\n";
$message .= "Content-Transfer-Encoding: 8bit\r\n\r\n";
$message .= $html . "\r\n\r\n";

$message .= "--{$boundary}--\r\n";

// ======================================================
// INVIO
// ======================================================

// IMPORTANTISSIMO:
// il quinto parametro -f forza l'envelope sender corretto.
// È ciò che ha fatto passare SPF/DMARC e arrivare in inbox.
$ok = mail(
    $to,
    $subject,
    $message,
    implode("\r\n", $headers),
    '-f' . FROM_EMAIL
);

if (!$ok) {
    json_response(false, [
        'error' => 'mail_failed',
        'message' => 'mail() ha restituito false.'
    ], 500);
}

json_response(true, [
    'to' => $to,
    'from' => FROM_EMAIL,
    'subject' => $subject,
    'time' => date('Y-m-d H:i:s'),
    'ip' => get_client_ip()
]);

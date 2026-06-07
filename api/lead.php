<?php
/**
 * lead.php — приём заявок с сайта ДСК МИН-1.
 * Валидация → honeypot → антиспам → rate-limit → запись в MySQL →
 * уведомления в 3 канала (Telegram / Max / e-mail). Каждый канал независим.
 *
 * Требует рядом: config.php (из config.sample.php) и папку PHPMailer/.
 * Ответ всегда JSON: {ok:true} | {ok:false,error:'…'}
 */
declare(strict_types=1);

// Полифил mbstring на случай хостинга без расширения (на reg.ru обычно есть).
if (!function_exists('mb_strlen'))   { function mb_strlen($s, $e = null) { return strlen((string)$s); } }
if (!function_exists('mb_substr'))   { function mb_substr($s, $start, $len = null) { return $len === null ? substr((string)$s, $start) : substr((string)$s, $start, $len); } }
if (!function_exists('mb_strtolower')) { function mb_strtolower($s) { return strtolower((string)$s); } }

$CONFIG_PATH = __DIR__ . '/config.php';
if (!is_file($CONFIG_PATH)) {
    header('Content-Type: application/json; charset=utf-8');
    http_response_code(500);
    echo json_encode(['ok' => false, 'error' => 'Сервер не настроен (нет config.php)'], JSON_UNESCAPED_UNICODE);
    exit;
}
$cfg = require $CONFIG_PATH;

/* ---------- CORS ---------- */
$origin = $_SERVER['HTTP_ORIGIN'] ?? '';
if ($origin !== '' && in_array($origin, $cfg['cors_origins'], true)) {
    header("Access-Control-Allow-Origin: $origin");
    header('Vary: Origin');
}
header('Access-Control-Allow-Methods: POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');
header('Content-Type: application/json; charset=utf-8');

$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
if ($method === 'OPTIONS') { http_response_code(204); exit; }
if ($method !== 'POST') {
    http_response_code(405);
    echo json_encode(['ok' => false, 'error' => 'Метод не разрешён'], JSON_UNESCAPED_UNICODE);
    exit;
}

/* ---------- тело запроса (text/plain JSON — без CORS-preflight) ---------- */
$raw  = file_get_contents('php://input') ?: '';
$data = json_decode($raw, true);
if (!is_array($data)) {
    echo json_encode(['ok' => false, 'error' => 'Некорректные данные'], JSON_UNESCAPED_UNICODE);
    exit;
}

/* ---------- honeypot: боты заполняют скрытые поля ---------- */
if (!empty($data['website']) || !empty($data['email_confirm'])) {
    echo json_encode(['ok' => true], JSON_UNESCAPED_UNICODE); // тихий «успех»
    exit;
}

/* ---------- поля ---------- */
$name    = trim((string)($data['name'] ?? ''));
$phone   = trim((string)($data['phone'] ?? ''));
$object  = trim((string)($data['object'] ?? ''));
$comment = trim((string)($data['comment'] ?? ''));
$consent = !empty($data['consent']);
$ua      = mb_substr((string)($data['userAgent'] ?? ''), 0, 255);
$ip      = $_SERVER['REMOTE_ADDR'] ?? '';                 // серверный IP надёжнее клиентского
$referer = mb_substr((string)($_SERVER['HTTP_REFERER'] ?? ''), 0, 255);

/* ---------- валидация (зеркало клиентской) ---------- */
$errors = [];
if (mb_strlen($name) < 2)                          $errors[] = 'Укажите имя';
if (strlen(preg_replace('/\D+/', '', $phone)) < 10) $errors[] = 'Укажите корректный телефон';
if (mb_strlen($object) < 2)                         $errors[] = 'Укажите объект или задачу';
if (!$consent)                                      $errors[] = 'Нужно согласие на обработку персональных данных';
if ($errors) {
    echo json_encode(['ok' => false, 'error' => implode('. ', $errors)], JSON_UNESCAPED_UNICODE);
    exit;
}
if (mb_strlen($comment) > 2000) $comment = mb_substr($comment, 0, 2000);

/* ---------- спам-фильтр (тихий дроп) ---------- */
$haystack = mb_strtolower("$name $object $comment");
foreach ($cfg['spam_patterns'] as $re) {
    if (@preg_match($re, $haystack)) {
        echo json_encode(['ok' => true], JSON_UNESCAPED_UNICODE);
        exit;
    }
}

/* ---------- БД ---------- */
try {
    $pdo = new PDO(
        "mysql:host={$cfg['db']['host']};dbname={$cfg['db']['name']};charset=utf8mb4",
        $cfg['db']['user'],
        $cfg['db']['pass'],
        [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC]
    );
} catch (Throwable $e) {
    echo json_encode(['ok' => false, 'error' => 'Временная ошибка. Позвоните нам, пожалуйста.'], JSON_UNESCAPED_UNICODE);
    exit;
}

/* ---------- rate-limit по IP ---------- */
try {
    $now    = time();
    $window = (int)$cfg['rate_limit']['window'];
    $max    = (int)$cfg['rate_limit']['max'];

    $st = $pdo->prepare('SELECT timestamps FROM rate_limit WHERE ip = ?');
    $st->execute([$ip]);
    $row = $st->fetch();

    $ts = $row ? (json_decode($row['timestamps'], true) ?: []) : [];
    $ts = array_values(array_filter($ts, fn($t) => (int)$t > $now - $window));

    if (count($ts) >= $max) {
        echo json_encode(['ok' => false, 'error' => 'Слишком много заявок подряд. Попробуйте через минуту или позвоните нам.'], JSON_UNESCAPED_UNICODE);
        exit;
    }
    $ts[] = $now;
    $tsJson = json_encode($ts);
    if ($row) {
        $pdo->prepare('UPDATE rate_limit SET timestamps = ?, updated_at = NOW() WHERE ip = ?')->execute([$tsJson, $ip]);
    } else {
        $pdo->prepare('INSERT INTO rate_limit (ip, timestamps, updated_at) VALUES (?, ?, NOW())')->execute([$ip, $tsJson]);
    }
} catch (Throwable $e) { /* rate-limit best-effort, не валим заявку */ }

/* ---------- сохранение заявки ---------- */
try {
    $st = $pdo->prepare(
        'INSERT INTO leads (created_at, ip, name, phone, comment, object, user_agent, referer)
         VALUES (NOW(), ?, ?, ?, ?, ?, ?, ?)'
    );
    $st->execute([$ip, $name, $phone, $comment, $object, $ua, $referer]);
    $leadId = (int)$pdo->lastInsertId();
} catch (Throwable $e) {
    echo json_encode(['ok' => false, 'error' => 'Не удалось сохранить заявку. Позвоните нам, пожалуйста.'], JSON_UNESCAPED_UNICODE);
    exit;
}

/* ---------- уведомления (best-effort, не влияют на ответ) ---------- */
$text = "🆕 Заявка с сайта ДСК МИН-1  (#$leadId)\n"
      . "Имя: $name\n"
      . "Телефон: $phone\n"
      . "Объект: $object\n"
      . ($comment !== '' ? "Комментарий: $comment\n" : '')
      . "IP: $ip\n"
      . 'Время: ' . date('d.m.Y H:i');

if (!empty($cfg['telegram']['enabled'])) { notify_telegram($cfg['telegram'], $text); }
if (!empty($cfg['max']['enabled']))      { notify_max($cfg['max'], $text); }
if (!empty($cfg['email']['enabled']))    { notify_email($cfg['email'], $leadId, $name, $phone, $object, $comment, $ip); }

echo json_encode(['ok' => true], JSON_UNESCAPED_UNICODE);

/* =================== helpers =================== */

function http_post_form(string $url, array $fields, int $timeout = 5): void
{
    if (!function_exists('curl_init')) return;
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_POST           => true,
        CURLOPT_POSTFIELDS     => http_build_query($fields),
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT        => $timeout,
        CURLOPT_CONNECTTIMEOUT => $timeout,
    ]);
    curl_exec($ch);
    curl_close($ch);
}

function notify_telegram(array $tg, string $text): void
{
    if (empty($tg['token']) || empty($tg['chat_ids'])) return;
    foreach ((array)$tg['chat_ids'] as $cid) {
        http_post_form("https://api.telegram.org/bot{$tg['token']}/sendMessage", [
            'chat_id'                  => $cid,
            'text'                     => $text,
            'disable_web_page_preview' => 'true',
        ]);
    }
}

function notify_max(array $max, string $text): void
{
    if (empty($max['token']) || empty($max['chat_ids'])) return;
    // ЗАГОТОВКА: точный endpoint Max Bot API подставим при получении токена.
    foreach ((array)$max['chat_ids'] as $cid) {
        http_post_form(rtrim($max['api_base'], '/') . '/messages?access_token=' . rawurlencode($max['token']), [
            'chat_id' => $cid,
            'text'    => $text,
        ]);
    }
}

function notify_email(array $em, int $leadId, string $name, string $phone, string $object, string $comment, string $ip): void
{
    $dir = __DIR__ . '/PHPMailer';
    foreach (['Exception.php', 'PHPMailer.php', 'SMTP.php'] as $f) {
        if (!is_file("$dir/$f")) return;
        require_once "$dir/$f";
    }
    try {
        $mail = new PHPMailer\PHPMailer\PHPMailer(true);
        $mail->isSMTP();
        $mail->Host       = $em['smtp_host'];
        $mail->Port       = (int)$em['smtp_port'];
        $mail->SMTPAuth   = true;
        $mail->Username   = $em['smtp_user'];
        $mail->Password   = $em['smtp_pass'];
        $mail->SMTPSecure = $em['smtp_secure'] === 'tls'
            ? PHPMailer\PHPMailer\PHPMailer::ENCRYPTION_STARTTLS
            : PHPMailer\PHPMailer\PHPMailer::ENCRYPTION_SMTPS;
        $mail->CharSet = 'UTF-8';
        $mail->setFrom($em['from'], $em['from_name']);
        foreach ((array)$em['to'] as $to) { $mail->addAddress($to); }
        $mail->Subject = "Заявка с сайта ДСК МИН-1 (#$leadId)";
        $mail->Body =
            "Новая заявка с сайта (#$leadId)\n\n" .
            "Имя: $name\nТелефон: $phone\nОбъект: $object\n" .
            ($comment !== '' ? "Комментарий: $comment\n" : '') .
            "IP: $ip\nВремя: " . date('d.m.Y H:i');
        $mail->send();
    } catch (Throwable $e) { /* e-mail best-effort */ }
}

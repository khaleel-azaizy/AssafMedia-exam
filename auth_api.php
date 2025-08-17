<?php

define("a328763fe27bba", true);
require_once __DIR__ . "/config.php"; 
header("Content-Type: application/json; charset=utf-8");
date_default_timezone_set(APP_TIMEZONE);

const OTP_TTL_MINUTES     = 10;
const RESEND_COOLDOWN_SEC = 30;
const MAX_PER_HOUR        = 4;
const MAX_PER_DAY         = 10;

const BREVO_API_KEY       = ""; 
const BREVO_SENDER_NAME   = "Whisper Login";
const BREVO_SENDER_EMAIL  = "no-reply@example.com";

function json_out(array $arr, int $code = 200) {
  http_response_code($code);
  echo json_encode($arr, JSON_UNESCAPED_UNICODE);
  exit;
}

function token_hash_from_header(): ?string {
  $candidates = [
    $_SERVER['HTTP_AUTHORIZATION'] ?? null,
    $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? null, // IIS/CGI/Apache variants
    $_SERVER['Authorization'] ?? null,
  ];
  $h = null;
  foreach ($candidates as $cand) {
    if ($cand && stripos($cand, 'Bearer ') === 0) { $h = $cand; break; }
  }

  // Fallback: apache_request_headers (case-insensitive)
  if (!$h && function_exists('apache_request_headers')) {
    $hdrs = array_change_key_case(apache_request_headers(), CASE_UPPER);
    if (!empty($hdrs['AUTHORIZATION']) && stripos($hdrs['AUTHORIZATION'], 'Bearer ') === 0) {
      $h = $hdrs['AUTHORIZATION'];
    }
  }

  if ($h && preg_match('/Bearer\s+([A-Za-z0-9]+)/', $h, $m)) {
    return hash('sha256', trim($m[1]));
  }

  // DEV convenience: allow token in query for manual browser testing
  if (defined('ENV') && ENV === 'dev' && !empty($_GET['access_token'])) {
    return hash('sha256', $_GET['access_token']);
  }

  return null;
}

function username_from_token_hash(mysqli $conn, string $token_hash): ?string {
  $q = $conn->prepare("SELECT username FROM auth_tokens WHERE token=? LIMIT 1");
  $q->bind_param("s", $token_hash);
  $q->execute();
  $row = $q->get_result()->fetch_assoc();
  return $row['username'] ?? null;
}

function db(): mysqli {
  $conn = get_mysqli_connection();
  if (!$conn) json_out(["ok" => false, "error" => "db_connect_failed"], 500);
  return $conn;
}

function hash256(string $s): string { return hash('sha256', $s); }

function sanitize_username(?string $u): string {
  $u = trim((string)$u);
  if ($u === "" || !preg_match('/^[a-zA-Z0-9_.-]{1,255}$/', $u)) return "";
  return $u;
}

function send_brevo_email(string $toEmail, string $subject, string $html): bool {
  if (BREVO_API_KEY === "" || $toEmail === "") {
    error_log("[DEV] Would send email to {$toEmail} | {$subject} | " . strip_tags($html));
    return true;
  }
  $payload = [
    "sender"      => ["name" => BREVO_SENDER_NAME, "email" => BREVO_SENDER_EMAIL],
    "to"          => [["email" => $toEmail]],
    "subject"     => $subject,
    "htmlContent" => $html
  ];
  $ch = curl_init("https://api.brevo.com/v3/smtp/email");
  curl_setopt_array($ch, [
    CURLOPT_POST           => true,
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_HTTPHEADER     => [
      "api-key: " . BREVO_API_KEY,
      "Content-Type: application/json"
    ],
    CURLOPT_POSTFIELDS     => json_encode($payload)
  ]);
  $resp = curl_exec($ch);
  $http = curl_getinfo($ch, CURLINFO_HTTP_CODE);
  $err  = curl_error($ch);
  curl_close($ch);
  if ($http >= 200 && $http < 300) return true;
  error_log("Brevo send failed: http=$http err=$err resp=$resp");
  return false;
}

$action   = $_POST['action'] ?? $_GET['action'] ?? '';
$honeypot = $_POST['company_url'] ?? $_GET['company_url'] ?? ''; 

if ($honeypot !== '') json_out(["ok" => true]);

$conn = db();

if ($action === 'request_otp') {
  $username = sanitize_username($_POST['username'] ?? $_GET['username'] ?? '');
  if ($username === "") json_out(["ok" => false, "error" => "username required"], 400);

  
  $stmt = $conn->prepare("SELECT username, COALESCE(email,'') AS email FROM users WHERE username=? LIMIT 1");
  $stmt->bind_param("s", $username);
  $stmt->execute();
  $user = $stmt->get_result()->fetch_assoc();
  if (!$user) json_out(["ok" => false, "error" => "user not found"], 404);

  // cooldown 30s from last OTP
  $q = $conn->prepare("SELECT created_at FROM auth_otps WHERE username=? ORDER BY id DESC LIMIT 1");
  $q->bind_param("s", $username); $q->execute();
  if ($row = $q->get_result()->fetch_assoc()) {
    $since = time() - strtotime($row['created_at']);
    if ($since < RESEND_COOLDOWN_SEC) {
      json_out(["ok" => false, "error" => "cooldown", "retry after sec" => RESEND_COOLDOWN_SEC - $since], 429);
    }
  }
  // per hour
  $q = $conn->prepare("SELECT COUNT(*) c FROM auth_otps WHERE username=? AND created_at >= (NOW() - INTERVAL 1 HOUR)");
  $q->bind_param("s", $username); $q->execute();
  $c_hour = $q->get_result()->fetch_assoc()['c'] ?? 0;
  if ($c_hour >= MAX_PER_HOUR) json_out(["ok" => false, "error" => "hour quota exceeded"], 429);
  // per day
  $q = $conn->prepare("SELECT COUNT(*) c FROM auth_otps WHERE username=? AND DATE(created_at) = CURRENT_DATE()");
  $q->bind_param("s", $username); $q->execute();
  $c_day = $q->get_result()->fetch_assoc()['c'] ?? 0;
  if ($c_day >= MAX_PER_DAY) json_out(["ok" => false, "error" => "day quota exceeded"], 429);

  // ---- Create & store OTP ----
  $otp       = strval(random_int(100000, 999999));
  $otp_hash  = hash256($otp);
  $expiresAt = date('Y-m-d H:i:s', time() + OTP_TTL_MINUTES * 60);

  $ins = $conn->prepare("INSERT INTO auth_otps (username, otp_hash, otp_expires_at) VALUES (?,?,?)");
  $ins->bind_param("sss", $username, $otp_hash, $expiresAt);
  $ins->execute();

  // ---- Send (or log) ----
  $html = "<p>Your login code is <strong>{$otp}</strong>. It expires in " . OTP_TTL_MINUTES . " minutes.</p>";
  $sent = send_brevo_email($user['email'], "Your login code", $html);
  if (!$sent) json_out(["ok" => false, "error" => "send_failed"], 500);

  // Return cooldown + TTL to client
  json_out(["ok" => true, "ttl_min" => OTP_TTL_MINUTES, "cooldown_sec" => RESEND_COOLDOWN_SEC]);
}

if ($action === 'verify_otp') {
  $username = sanitize_username($_POST['username'] ?? $_GET['username'] ?? '');
  $code     = trim((string)($_POST['otp'] ?? $_GET['otp'] ?? ''));
  if ($username === "" || $code === "") json_out(["ok" => false, "error" => "missing_params"], 400);
  if (!preg_match('/^\d{6}$/', $code)) json_out(["ok" => false, "error" => "invalid_code_format"], 400);

  // make sure the user exists (even if no email)
  $stmt = $conn->prepare("SELECT username FROM users WHERE username=? LIMIT 1");
  $stmt->bind_param("s", $username); $stmt->execute();
  if (!$stmt->get_result()->fetch_assoc()) json_out(["ok" => false, "error" => "user not found"], 404);

  // take latest, unverified, not-expired OTP
  $q = $conn->prepare("SELECT id, otp_hash FROM auth_otps
                       WHERE username=? AND verified_at IS NULL
                         AND otp_expires_at >= NOW()
                       ORDER BY id DESC LIMIT 1");
  $q->bind_param("s", $username);
  $q->execute();
  $row = $q->get_result()->fetch_assoc();
  if (!$row) json_out(["ok" => false, "error" => "no_valid_otp"], 400);

  if (!hash_equals($row['otp_hash'], hash256($code))) {
    json_out(["ok" => false, "error" => "invalid_code"], 401);
  }

  // mark verified
  $upd = $conn->prepare("UPDATE auth_otps SET verified_at = NOW() WHERE id = ?");
  $upd->bind_param("i", $row['id']); $upd->execute();

  // issue token (store SHA-256; give plain to client)
  $token_plain = bin2hex(random_bytes(32));
  $token_hash  = hash256($token_plain);
  $expiresAt   = date('Y-m-d H:i:s', time() + 7 * 24 * 60 * 60); // 7 days

  $ins = $conn->prepare("INSERT INTO auth_tokens (username, token, expires_at) VALUES (?,?,?)");
  $ins->bind_param("sss", $username, $token_hash, $expiresAt);
  $ins->execute();

  json_out(["ok" => true, "token" => $token_plain, "expires_at" => $expiresAt]);
}

if ($action === 'logout' || $action === 'logout_all') {
  $conn = db();
  $th = token_hash_from_header();
  if (!$th) json_out(["ok"=>true]); // no token? treat as already logged out

  if ($action === 'logout_all') {
    $u = username_from_token_hash($conn, $th);
    if ($u) {
      $q = $conn->prepare("UPDATE auth_tokens SET revoked=1 WHERE username=?");
      $q->bind_param("s", $u);
      $q->execute();
    }
  } else {
    // single-token logout
    $q = $conn->prepare("UPDATE auth_tokens SET revoked=1 WHERE token=?");
    $q->bind_param("s", $th);
    $q->execute();
  }

  json_out(["ok"=>true]);
}

// default
json_out(["ok" => false, "error" => "unknown_action"], 400);

<?php
// Backend for the blog admin panel (admin/index.html).
// Reads and writes the blog's files directly on the web server.

declare(strict_types=1);

$secure = !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off';
session_name('blogadmin');
session_set_cookie_params(['lifetime' => 0, 'path' => '/', 'secure' => $secure, 'httponly' => true, 'samesite' => 'Strict']);
session_start();

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');
header('X-Content-Type-Options: nosniff');

const ROOT = __DIR__ . '/..';
const MAX_FILE = 2 * 1024 * 1024;       // generated pages / posts
const MAX_IMAGE = 5 * 1024 * 1024;      // uploaded images
const RESERVED = ['posts', 'images'];   // folders inside blog/ that are not posts

function out($data, int $code = 200): void
{
    http_response_code($code);
    echo json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    exit;
}

function fail(string $msg, int $code = 400): void
{
    out(['error' => $msg], $code);
}

function logged_in(): bool
{
    return !empty($_SESSION['admin']);
}

function csrf(): string
{
    if (empty($_SESSION['csrf'])) {
        $_SESSION['csrf'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf'];
}

function require_auth(): void
{
    if (!logged_in()) {
        fail('Your session has expired. Please sign in again.', 401);
    }
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && !hash_equals(csrf(), $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '')) {
        fail('Security check failed. Reload the page and try again.', 403);
    }
}

// Which files the admin may touch. Returns 'read', 'write' or 'delete' capability list.
function file_rules(string $path): array
{
    if ($path === 'blog/_template.html') {
        return ['read'];
    }
    if (in_array($path, ['blog/posts.json', 'blog/index.html', 'sitemap.xml'], true)) {
        return ['read', 'write'];
    }
    if (preg_match('~^blog/posts/([a-z0-9]+(?:-[a-z0-9]+)*)\.md$~', $path)) {
        return ['read', 'write', 'delete'];
    }
    if (preg_match('~^blog/([a-z0-9]+(?:-[a-z0-9]+)*)/index\.html$~', $path, $m) && !in_array($m[1], RESERVED, true)) {
        return ['read', 'write', 'delete'];
    }
    return [];
}

function write_file(string $path, string $content): void
{
    $full = ROOT . '/' . $path;
    $dir = dirname($full);
    if (!is_dir($dir) && !mkdir($dir, 0755, true)) {
        throw new RuntimeException('Could not create folder ' . dirname($path));
    }
    $tmp = $full . '.tmp' . bin2hex(random_bytes(4));
    if (file_put_contents($tmp, $content, LOCK_EX) === false || !rename($tmp, $full)) {
        @unlink($tmp);
        throw new RuntimeException('Could not save ' . $path . '. Check the folder permissions in File Manager.');
    }
}

function delete_file(string $path): void
{
    $full = ROOT . '/' . $path;
    if (is_file($full) && !unlink($full)) {
        throw new RuntimeException('Could not delete ' . $path);
    }
    // Remove the now-empty post folder (blog/<slug>/)
    if (preg_match('~^blog/[a-z0-9-]+/index\.html$~', $path)) {
        @rmdir(dirname($full));
    }
}

// ---- Brute-force protection: 5 failed sign-ins per IP locks it for 15 minutes ----
function attempts_file(): string
{
    return sys_get_temp_dir() . '/blogadmin-' . md5(__DIR__) . '.json';
}

function attempts_load(): array
{
    $data = @json_decode((string) @file_get_contents(attempts_file()), true);
    $now = time();
    return array_filter(is_array($data) ? $data : [], function ($a) use ($now) {
        return $a['t'] > $now - 900;
    });
}

$action = $_GET['action'] ?? '';
$method = $_SERVER['REQUEST_METHOD'];
$body = [];
if ($method === 'POST' && stripos($_SERVER['CONTENT_TYPE'] ?? '', 'application/json') === 0) {
    $body = json_decode((string) file_get_contents('php://input'), true) ?: [];
}

try {
    switch ($action) {
        case 'me':
            out(['loggedIn' => logged_in(), 'csrf' => csrf()]);

        case 'login':
            if ($method !== 'POST') fail('Method not allowed', 405);
            $config = require __DIR__ . '/config.php';
            $password = (string) ($config['password'] ?? '');
            if ($password === '' || $password === 'CHANGE-ME') {
                fail('Set your password first: open admin/config.php in Hostinger File Manager and replace CHANGE-ME with your own password.', 403);
            }
            $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
            $attempts = attempts_load();
            $mine = array_filter($attempts, function ($a) use ($ip) { return $a['ip'] === $ip; });
            if (count($mine) >= 5) {
                fail('Too many wrong passwords. Try again in 15 minutes.', 429);
            }
            if (!hash_equals($password, (string) ($body['password'] ?? ''))) {
                $attempts[] = ['ip' => $ip, 't' => time()];
                @file_put_contents(attempts_file(), json_encode(array_values($attempts)), LOCK_EX);
                sleep(1);
                fail('Wrong password.', 401);
            }
            session_regenerate_id(true);
            $_SESSION['admin'] = true;
            $_SESSION['csrf'] = bin2hex(random_bytes(32));
            out(['ok' => true, 'csrf' => $_SESSION['csrf']]);

        case 'logout':
            require_auth();
            $_SESSION = [];
            session_destroy();
            out(['ok' => true]);

        case 'read':
            require_auth();
            $path = (string) ($_GET['path'] ?? '');
            if (!in_array('read', file_rules($path), true)) fail('Not allowed: ' . $path, 403);
            $full = ROOT . '/' . $path;
            if (!is_file($full)) out(['exists' => false]);
            out(['exists' => true, 'content' => file_get_contents($full)]);

        case 'write':
            require_auth();
            if ($method !== 'POST') fail('Method not allowed', 405);
            $files = $body['files'] ?? null;
            if (!is_array($files) || !$files) fail('Nothing to save.');
            // Check every file before changing anything
            foreach ($files as $path => $content) {
                $rules = file_rules((string) $path);
                if ($content === null ? !in_array('delete', $rules, true) : (!in_array('write', $rules, true) || !is_string($content))) {
                    fail('Not allowed: ' . $path, 403);
                }
                if (is_string($content) && strlen($content) > MAX_FILE) fail($path . ' is too large.');
            }
            foreach ($files as $path => $content) {
                $content === null ? delete_file((string) $path) : write_file((string) $path, $content);
            }
            out(['ok' => true]);

        case 'upload':
            require_auth();
            if ($method !== 'POST') fail('Method not allowed', 405);
            $f = $_FILES['image'] ?? null;
            if (!$f || $f['error'] !== UPLOAD_ERR_OK) {
                fail($f && in_array($f['error'], [UPLOAD_ERR_INI_SIZE, UPLOAD_ERR_FORM_SIZE], true) ? 'That image is too large for your hosting upload limit.' : 'Upload failed.');
            }
            if ($f['size'] > MAX_IMAGE) fail('That image is over 5 MB. Please resize it first.');
            $types = [IMAGETYPE_JPEG => 'jpg', IMAGETYPE_PNG => 'png', IMAGETYPE_GIF => 'gif', IMAGETYPE_WEBP => 'webp'];
            $info = @getimagesize($f['tmp_name']);
            if (!$info || !isset($types[$info[2]])) fail('Please upload a JPG, PNG, GIF or WebP image.');
            $base = strtolower(preg_replace('~[^a-zA-Z0-9]+~', '-', pathinfo((string) $f['name'], PATHINFO_FILENAME)));
            $base = trim(substr(trim($base, '-'), 0, 50), '-') ?: 'image';
            $name = date('Y-m-d') . '-' . $base . '-' . bin2hex(random_bytes(3)) . '.' . $types[$info[2]];
            $dir = ROOT . '/blog/images';
            if (!is_dir($dir) && !mkdir($dir, 0755, true)) fail('Could not create blog/images folder.', 500);
            if (!move_uploaded_file($f['tmp_name'], $dir . '/' . $name)) fail('Could not save the image.', 500);
            @chmod($dir . '/' . $name, 0644);
            out(['path' => 'images/' . $name]);

        default:
            fail('Unknown action', 404);
    }
} catch (Throwable $e) {
    fail($e->getMessage(), 500);
}

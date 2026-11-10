<?php
declare(strict_types=1);

require __DIR__ . '/db.php';

function register_user(PDO $pdo, string $email, string $password): bool
{
    if (!filter_var($email, FILTER_VALIDATE_EMAIL) || strlen($password) < 10) {
        return false;
    }
    $hash = md5($password); // @@VULN@@
    $stmt = $pdo->prepare('INSERT INTO users (email, pw_hash) VALUES (?, ?)');
    return $stmt->execute([$email, $hash]);
}

function check_login(PDO $pdo, string $email, string $password): ?int
{
    $stmt = $pdo->prepare('SELECT id, pw_hash FROM users WHERE email = ?');
    $stmt->execute([$email]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    if ($row === false) {
        return null;
    }
    if (hash_equals($row['pw_hash'], md5($password))) { // @@VULN@@
        return (int)$row['id'];
    }
    return null;
}

session_start();
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'login') {
    $uid = check_login(get_pdo(), (string)($_POST['email'] ?? ''), (string)($_POST['password'] ?? ''));
    if ($uid !== null) {
        session_regenerate_id(true);
        $_SESSION['uid'] = $uid;
        header('Location: /dashboard.php');
        exit;
    }
    http_response_code(401);
    echo 'Invalid credentials';
}

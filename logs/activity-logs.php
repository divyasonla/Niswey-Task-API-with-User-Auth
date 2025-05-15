<?php
require_once __DIR__. '/../vendor/autoload.php';
require_once __DIR__. '/../db/config.php';
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

$token = $_COOKIE['token'] ?? null;

if (!$token) {
    http_response_code(401);
    echo json_encode(['error' => 'Unauthorized']);
    exit;
}

try {
    $decoded = JWT::decode($token, new Key($jwt_secret, 'HS256'));
    $user_id = $decoded->data->user_id;
    $role = $decoded->data->role;

    if ($role === 'admin') {
        $stmt = $pdo->query("SELECT * FROM activity_logs ORDER BY created_at DESC");
    } else {
        $stmt = $pdo->prepare("SELECT * FROM activity_logs WHERE user_id = ? ORDER BY created_at DESC");
        $stmt->execute([$user_id]);
    }

    $logs = $stmt->fetchAll(PDO::FETCH_ASSOC);

    header('Content-Type: application/json');
    echo json_encode($logs);

} catch (Exception $e) {
    http_response_code(401);
    echo json_encode(['error' => 'Invalid token']);
}
?>

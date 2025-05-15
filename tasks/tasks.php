<?php
require_once __DIR__ . '/../vendor/autoload.php';
require_once __DIR__ . '/../db/config.php';
require_once __DIR__ . '/../utils/jwt.php'; 

header('Content-Type: application/json');

$method = $_SERVER['REQUEST_METHOD'];
$token = $_COOKIE['token'] ?? null;

if (!$token) {
    http_response_code(401);
    echo json_encode(['error' => 'Unauthorized: Token missing']);
    exit;
}

try {
    $decoded = decodeJWT($token); 
    $user_id = $decoded->data->user_id;
    $user_role = $decoded->data->role;
} catch (Exception $e) {
    http_response_code(401);
    echo json_encode(['error' => 'Invalid token']);
    exit;
}

function log_activity($pdo, $user_id, $task_id, $action) {
    $stmt = $pdo->prepare("INSERT INTO activity_logs (user_id, task_id, action) VALUES (?, ?, ?)");
    $stmt->execute([$user_id, $task_id, $action]);
}

$input = json_decode(file_get_contents("php://input"), true);
if (!$input) {
    $input = $_POST;
}

switch ($method) {
    case 'GET':
        if ($user_role === 'admin') {
            $stmt = $pdo->query("SELECT * FROM tasks WHERE deleted_at IS NULL");
        } else {
            $stmt = $pdo->prepare("SELECT * FROM tasks WHERE user_id = ? AND deleted_at IS NULL");
            $stmt->execute([$user_id]);
        }
        $tasks = $stmt->fetchAll(PDO::FETCH_ASSOC);
        echo json_encode($tasks);
        break;

    case 'POST':
        $title = trim($input['title'] ?? '');
        $desc = trim($input['description'] ?? '');

        if (!$title) {
            http_response_code(400);
            echo json_encode(['error' => 'Title is required']);
            exit;
        }

        $stmt = $pdo->prepare("INSERT INTO tasks (user_id, title, description) VALUES (?, ?, ?)");
        $stmt->execute([$user_id, $title, $desc]);
        $task_id = $pdo->lastInsertId();

        log_activity($pdo, $user_id, $task_id, 'created');
        echo json_encode(['message' => 'Task created']);
        break;

    case 'PUT':
        parse_str($_SERVER['QUERY_STRING'], $query);
        $task_id = $query['id'] ?? null;

        if (!$task_id) {
            http_response_code(400);
            echo json_encode(['error' => 'Task ID required']);
            exit;
        }

        if ($user_role === 'admin') {
            $stmt = $pdo->prepare("SELECT * FROM tasks WHERE task_id = ? AND deleted_at IS NULL");
            $stmt->execute([$task_id]);
        } else {
            $stmt = $pdo->prepare("SELECT * FROM tasks WHERE task_id = ? AND user_id = ? AND deleted_at IS NULL");
            $stmt->execute([$task_id, $user_id]);
        }

        if (!$stmt->fetch()) {
            http_response_code(403);
            echo json_encode(['error' => 'Unauthorized or task not found']);
            exit;
        }

        $title = trim($input['title'] ?? '');
        $desc = trim($input['description'] ?? '');

        $stmt = $pdo->prepare("UPDATE tasks SET title = ?, description = ? WHERE task_id = ?");
        $stmt->execute([$title, $desc, $task_id]);

        log_activity($pdo, $user_id, $task_id, 'updated');
        echo json_encode(['message' => 'Task updated']);
        break;

    case 'DELETE':
        parse_str($_SERVER['QUERY_STRING'], $query);
        $task_id = $query['id'] ?? null;

        if (!$task_id) {
            http_response_code(400);
            echo json_encode(['error' => 'Task ID required']);
            exit;
        }

        if ($user_role === 'admin') {
            $stmt = $pdo->prepare("UPDATE tasks SET deleted_at = NOW() WHERE task_id = ?");
            $stmt->execute([$task_id]);
        } else {
            $stmt = $pdo->prepare("UPDATE tasks SET deleted_at = NOW() WHERE task_id = ? AND user_id = ?");
            $stmt->execute([$task_id, $user_id]);
        }

        if ($stmt->rowCount() > 0) {
            log_activity($pdo, $user_id, $task_id, 'deleted');
            echo json_encode(['message' => 'Task deleted']);
        } else {
            http_response_code(403);
            echo json_encode(['error' => 'Forbidden']);
        }
        break;

    default:
        http_response_code(405);
        echo json_encode(['error' => 'Method Not Allowed']);
        break;
}

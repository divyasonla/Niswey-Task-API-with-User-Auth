<?php
require_once __DIR__ . '/../vendor/autoload.php';
require_once __DIR__ . '/../utils/jwt.php';

header('Content-Type: application/json');

/**
 * Authorize a request using JWT from the Authorization header.
 * Optionally check for a required role.
 *
 * @param string|null $roleRequired
 * @return object|null
 */
function isAuthorized($roleRequired = null) {
    $headers = getallheaders();
    $authHeader = $headers['Authorization'] ?? $headers['authorization'] ?? null;

    if (!$authHeader || !str_starts_with($authHeader, 'Bearer ')) {
        http_response_code(401);
        echo json_encode(['message' => 'Authorization token not found']);
        exit;
    }

    $token = str_replace('Bearer ', '', $authHeader);
    $decoded = decodeToken($token); // From utils/jwt.php

    if (!$decoded) {
        http_response_code(401);
        echo json_encode(['message' => 'Invalid or expired token']);
        exit;
    }

    if ($roleRequired && $decoded->data->role !== $roleRequired && $decoded->data->role !== 'admin') {
        http_response_code(403);
        echo json_encode(['message' => 'Forbidden: Insufficient role']);
        exit;
    }

    return $decoded;
}

<?php
require_once __DIR__ . '/../vendor/autoload.php';

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

const JWT_SECRET = 'V2zT9QFg6gR8j2WiL7Z1XY3tK8pV3A7G5Qm1kD5n9sB8v2CpZ9zM8hHhF4wP3Rt';

function generateJWT($user) {
    $payload = [
        'iat' => time(),
        'exp' => time() + 3600,
        'data' => [
            'user_id' => $user['user_id'],
            'user_name' => $user['user_name'],
            'role' => $user['role'],
        ]
    ];
    return JWT::encode($payload, JWT_SECRET, 'HS256');
}

function decodeJWT($token) {
    return JWT::decode($token, new Key(JWT_SECRET, 'HS256'));
}


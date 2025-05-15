<?php

$host = 'localhost';
$db = 'php';
$user = 'root';
$pass = 'divya';

try {
    $pdo = new PDO("mysql:host=$host;dbname=$db", $user, $pass);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (Exception $e) {
    die("DB Error: " . $e->getMessage());
}

$jwt_secret = "V2zT9QFg6gR8j2WiL7Z1XY3tK8pV3A7G5Qm1kD5n9sB8v2CpZ9zM8hHhF4wP3Rt"; 
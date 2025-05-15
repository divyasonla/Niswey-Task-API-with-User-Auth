<?php
require __DIR__ . '/../vendor/autoload.php';
require __DIR__ . '/../db/config.php';
require __DIR__ . '/../utils/jwt.php';
require __DIR__ . '/../utils/helpers.php';

use PDO;

if (isset($_POST['login'])) {
    $email = sanitize($_POST['email'] ?? '');
    $password = sanitize($_POST['password'] ?? '');

    try {
        $stmt = $pdo->prepare("SELECT * FROM users WHERE user_email = :email LIMIT 1");
        $stmt->execute(['email' => $email]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($user && password_verify($password, $user['user_password'])) {
            $token = generateJWT($user);

            setcookie('token', $token, [
                'expires' => time() + 3600,
                'path' => '/',
                'httponly' => true,
                'secure' => false, 
                'samesite' => 'Lax'
            ]);

            header("Location: /tasks/tasks.html"); 
            exit;
        } else {
            $error = "Invalid email or password!";
        }
    } catch (Exception $e) {
        $error = "An error occurred. Please try again.";
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login & Registration</title>
</head>
<body>
<div class="container">


    <h2 class="my-5">Login</h2>
    <?php if (isset($error)) echo "<div class='alert alert-danger'>{$error}</div>"; ?>
    <form method="POST">
        <div class="form-group">
            <label for="email">Email</label>
            <input type="email" name="email" class="form-control" required autofocus>
        </div>
        <div class="form-group">
            <label for="password">Password</label>
            <input type="password" name="password" class="form-control" required>
        </div>
        <button type="submit" name="login" class="btn btn-primary">Login</button>
    </form>
</div>
</body>
<style>
    * {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
    font-family: 'Segoe UI', sans-serif;
}

body {
    background-color: #eef2f3;
    padding: 20px;
    display: flex;
    justify-content: center;
    align-items: center;
    height: 100vh;
}

.container {
    background-color: #fff;
    padding: 30px;
    width: 100%;
    max-width: 400px;
    border-radius: 10px;
    box-shadow: 0 8px 20px rgba(0, 0, 0, 0.1);
}

h2 {
    margin-bottom: 20px;
    text-align: center;
    color: #333;
}

.form-group {
    margin-bottom: 18px;
}

label {
    display: block;
    margin-bottom: 8px;
    font-weight: bold;
    color: #444;
}

input[type="email"],
input[type="password"] {
    width: 100%;
    padding: 10px 12px;
    border: 1px solid #ccc;
    border-radius: 6px;
    font-size: 16px;
    transition: border 0.3s;
}

input:focus {
    border-color: #007bff;
    outline: none;
}

.btn-primary {
    background-color: #007bff;
    color: #fff;
    padding: 12px;
    width: 100%;
    border: none;
    border-radius: 6px;
    font-size: 16px;
    cursor: pointer;
    transition: background 0.3s;
}

.btn-primary:hover {
    background-color: #0056b3;
}

.alert {
    background-color: #f8d7da;
    color: #842029;
    padding: 12px;
    margin-bottom: 20px;
    border-left: 5px solid #f5c2c7;
    border-radius: 4px;
}

</style>
</html>

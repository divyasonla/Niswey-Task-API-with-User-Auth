<?php
require __DIR__ . '/../vendor/autoload.php';
require __DIR__ . '/../db/config.php';
require __DIR__ . '/../utils/helpers.php';
require __DIR__ . '/../utils/jwt.php';

if (isset($_POST['register'])) {
    $name = sanitize($_POST['name'] ?? '');
    $email = sanitize($_POST['email'] ?? '');
    $password = sanitize($_POST['password'] ?? '');
    $role = sanitize($_POST['role'] ?? '');

    if (!$name || !$email || !$password || !$role) {
        $error = "All fields are required.";
    } else {
        try {
            $query = "SELECT * FROM users WHERE user_email = :email";
            $statement = $pdo->prepare($query); 
            $statement->execute(['email' => $email]);
            $user = $statement->fetch(PDO::FETCH_ASSOC);

            if ($user) {
                $error = "Email already exists!";
            } else {
                $hashedPassword = password_hash($password, PASSWORD_DEFAULT);

                $insert_query = "INSERT INTO users (user_email, user_password, user_name, role) 
                                 VALUES (:email, :password, :name, :role)";
                $stmt = $pdo->prepare($insert_query);  
                $stmt->execute([
                    'email' => $email,
                    'password' => $hashedPassword,
                    'name' => $name,
                    'role' => $role
                ]);

                $user_id = $pdo->lastInsertId();
                $new_user = [
                    'user_id' => $user_id,
                    'user_name' => $name,
                    'role' => $role
                ];

                $token = generateJWT($new_user);

                setcookie('token', $token, [
                    'expires' => time() + 3600,
                    'path' => '/',
                    'httponly' => true,
                    'secure' => false,
                    'samesite' => 'Lax'
                ]);

                header("Location: /auth/login.php"); 
                exit();
            }
        } catch (Exception $e) {
            $error = "An error occurred. Please try again.";
        }
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Register</title>

</head>
<body>
    <div class="container">
        <h2 class="my-5">Register</h2>
        <?php if (isset($error)) echo "<div class='alert alert-danger'>{$error}</div>"; ?>
        <form method="POST">
            <div class="form-group">
                <label for="name">Name</label>
                <input type="text" name="name" class="form-control" required>
            </div>
            <div class="form-group">
                <label for="email">Email</label>
                <input type="email" name="email" class="form-control" required>
            </div>
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" name="password" class="form-control" required>
            </div>
            <div class="form-group">
                <label for="role">Role</label>
                <select name="role" class="form-control" required>
                    <option value="user">User</option>
                    <option value="admin">Admin</option>
                </select>
            </div>
            <button type="submit" name="register" class="btn btn-primary">Register</button>
            <a href="/auth/login.php" class="btn btn-secondary">Login</a>
        </form>
    </div>
</body>
<<style>
* {
    box-sizing: border-box;
    margin: 0;
    padding: 0;
    font-family: Arial, sans-serif;
}

body {
    background-color: #f4f4f4;
    padding: 20px;
}

.container {
    max-width: 500px;
    background-color: #fff;
    margin: 50px auto;
    padding: 30px;
    border-radius: 8px;
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
}

h2 {
    margin-bottom: 25px;
    text-align: center;
    color: #333;
}

.form-group {
    margin-bottom: 20px;
}

label {
    display: block;
    margin-bottom: 8px;
    color: #333;
    font-weight: bold;
}

input,
select {
    width: 100%;
    padding: 10px;
    border: 1px solid #ccc;
    border-radius: 4px;
    font-size: 16px;
}

input:focus,
select:focus {
    border-color: #007bff;
    outline: none;
}

.form-actions {
    display: flex;
    justify-content: space-between;
    align-items: center;
}

.btn-primary,
.btn-secondary {
    text-decoration: none;
    padding: 10px 20px;
    border: none;
    border-radius: 4px;
    font-size: 16px;
    cursor: pointer;
    display: inline-block;
    text-align: center;
}

.btn-primary {
    background-color: #007bff;
    color: #fff;
}

.btn-primary:hover {
    background-color: #0056b3;
}

.btn-secondary {
    background-color: #6c757d;
    color: #fff;
}

.btn-secondary:hover {
    background-color: #545b62;
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

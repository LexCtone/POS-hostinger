<?php
session_start();
$error_message = '';

// Generate CSRF token if it doesn't exist
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Handle POST request
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Verify CSRF token
    if (!hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        die('CSRF token mismatch');
    }

    // Include database connection
    include('connect.php'); // Ensure this file contains a MySQLi connection ($conn)

    // Load the .env.php file
    $env = require __DIR__ . '/.env.php'; // Ensure this is the correct path to .env.php

    // Access the encryption key and decode it
    $key = base64_decode($env['ENCRYPTION_KEY']); // Decode the encryption key

    // Sanitize and assign user inputs
    $username = trim($_POST['username']);
    $password = trim($_POST['password']);
    $selected_role = trim($_POST['role']);

    // Prepare SQL query to check for user credentials
    $query = 'SELECT password, iv, role, id, username FROM accounts WHERE username = ? AND status = 1';
    if ($stmt = $conn->prepare($query)) {
        $stmt->bind_param('s', $username);
        $stmt->execute();
        $result = $stmt->get_result();

        // Check if user exists and verify password
        if ($result->num_rows > 0) {
            $user = $result->fetch_assoc();

            // Decrypt the stored password
            $cipher = "AES-256-CBC";
            $iv = hex2bin($user['iv']); // Convert IV from hex to binary

            // Decrypt the password
            $decryptedPassword = openssl_decrypt($user['password'], $cipher, $key, 0, $iv);

            // Debug output
            // Uncomment for debugging purposes
            // error_log("Decrypted Password: " . htmlspecialchars($decryptedPassword));
            // error_log("Input Password: " . htmlspecialchars($password));
            // error_log("Selected Role: " . htmlspecialchars($selected_role));
            // error_log("User Role from Database: " . htmlspecialchars($user['role']));

            // Compare the decrypted password with the input password
            if ($decryptedPassword === $password && $user['role'] === $selected_role) {
                // Store user info in session variables
                $_SESSION['user_id'] = $user['id'];
                $_SESSION['role'] = $user['role'];
                $_SESSION['username'] = $user['username'];
                session_regenerate_id(true); // Prevent session fixation

                // Redirect based on role
                switch ($selected_role) {
                    case 'admin':
                        header('Location: Dashboard.php');
                        break;
                    case 'cashier':
                        header('Location: dash/Cashier_dashboard.php');
                        break;
                    default:
                        $error_message = 'Invalid role selected.';
                        break;
                }
                exit();
            } else {
                $error_message = 'Invalid password or role. Please try again.';
            }
        } else {
            $error_message = 'Invalid username or account is inactive. Please try again or contact an administrator.';
        }

        $stmt->close(); // Close the statement only if it was created
    } else {
        $error_message = 'Database query failed: ' . htmlspecialchars($conn->error);
    }

    $conn->close();
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>St Vincent Hardware Login</title>
    <link rel="stylesheet" href="CSS/login.css">
</head>
<body id="loginBody">
    <div class="container">
        <img src="logo.jpg" alt="LOGO">
        <?php if (!empty($error_message)) { ?>
            <div class="error">
                <p><?= htmlspecialchars($error_message) ?></p>
            </div>
        <?php } ?>
        <form action="Login.php" method="POST">
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
            <input type="text" name="username" placeholder="Username" required><br>
            <input type="password" name="password" placeholder="Password" required><br>
            <select name="role" required>
                <option value="" disabled selected>Select Role</option>
                <option value="admin">Admin</option>
                <option value="cashier">Cashier</option>
            </select><br>
            <input class="submit" type="submit" value="Login">
        </form>
    </div>
</body>
</html>

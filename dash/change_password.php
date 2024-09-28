<?php
session_start();
include '../connect.php';

header('Content-Type: application/json');

if (!isset($_SESSION['user_id']) || $_SESSION['role'] !== 'cashier') {
    echo json_encode(['success' => false, 'message' => 'Unauthorized access']);
    exit();
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $currentPassword = $_POST['currentPassword'];
    $newPassword = $_POST['newPassword'];
    $userId = $_SESSION['user_id'];

    // Verify current password
    $stmt = $conn->prepare("SELECT password FROM accounts WHERE id = ?");
    $stmt->bind_param("i", $userId);
    $stmt->execute();
    $result = $stmt->get_result();
    $user = $result->fetch_assoc();
    $stmt->close();

    // Check if the user exists and verify the current password
    if (!$user || !password_verify($currentPassword, $user['password'])) {
        echo json_encode(['success' => false, 'message' => 'Current password is incorrect']);
        exit();
    }

    // Validate the new password
    if (strlen($newPassword) < 8) {
        echo json_encode(['success' => false, 'message' => 'New password must be at least 8 characters long']);
        exit();
    }

    // Update password
    $hashedPassword = password_hash($newPassword, PASSWORD_DEFAULT);
    $stmt = $conn->prepare("UPDATE accounts SET password = ? WHERE id = ?");
    $stmt->bind_param("si", $hashedPassword, $userId);

    if ($stmt->execute()) {
        // Log the user out after a successful password change
        session_destroy(); // End the current session
        echo json_encode(['success' => true, 'message' => 'Password updated successfully. Please log in again.']);
    } else {
        echo json_encode(['success' => false, 'message' => 'Failed to update password']);
    }
    $stmt->close();
} else {
    echo json_encode(['success' => false, 'message' => 'Invalid request method']);
}

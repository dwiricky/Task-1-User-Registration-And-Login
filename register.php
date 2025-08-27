<?php
// register.php
include 'db.php';

$registerError = '';
$registerSuccess = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = $_POST['username'];
    $password = $_POST['password'];
    $email = $_POST['email'] ?? '';

    // Basic server-side validation
    if (empty($username) || empty($password) || empty($email)) {
        $registerError = 'Semua bidang wajib diisi.';
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $registerError = 'Format email tidak valid!';
    } else {
        // Hash password
        $hashedPassword = password_hash($password, PASSWORD_DEFAULT);

        // Simpan ke database
        // Pastikan kolom di tabel users: username, password, email
        $stmt = $conn->prepare('INSERT INTO users (username, password, email) VALUES (?, ?, ?)');
        $stmt->bind_param('sss', $username, $hashedPassword, $email);
        if ($stmt->execute()) {
            $registerSuccess = 'Registrasi berhasil!';
        } else {
            // Cek duplikasi di username atau email
            if ($stmt->errno === 1062) {
                // Mendeteksi duplikasi pada kolom unik; bisa lebih spesifik jika ada constraint terpisah
                $registerError = 'Username atau Email sudah digunakan!';
            } else {
                $registerError = 'Registrasi gagal: ' . $stmt->error;
            }
        }
        $stmt->close();
    }
}
?>

<!DOCTYPE html>
<html>
<head>
    <title>Register</title>
    <style>
        body { font-family: Arial, sans-serif; background: #f2f2f2; }
        .register-container {
            background: #fff;
            padding: 30px;
            margin: 80px auto;
            width: 350px;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }
        .register-container h2 { text-align: center; margin-bottom: 20px; }
        .register-container input[type="text"],
        .register-container input[type="password"],
        .register-container input[type="email"] {
            width: 100%; padding: 10px; margin: 8px 0 16px 0; border: 1px solid #ccc; border-radius: 4px;
        }
        .register-container button {
            width: 100%; padding: 10px; background: #28a745; color: #fff; border: none; border-radius: 4px;
            cursor: pointer;
        }
        .register-container button:hover { background: #218838; }
        .error { color: red; text-align: center; margin-bottom: 10px; }
        .success { color: green; text-align: center; margin-bottom: 10px; }
        label { display: block; font-size: 14px; margin-bottom: 6px; }
    </style>
</head>
<body>
    <div class="register-container">
        <h2>Register</h2>
        <?php if ($registerError): ?>
            <div class="error"><?= htmlspecialchars($registerError) ?></div>
        <?php endif; ?>
        <?php if ($registerSuccess): ?>
            <div class="success"><?= htmlspecialchars($registerSuccess) ?></div>
        <?php endif; ?>
        <form method="POST" action="">
            <label for="username">Username</label>
            <input type="text" id="username" name="username" placeholder="Username" required>

            <label for="email">Email</label>
            <input type="email" id="email" name="email" placeholder="Email" required>

            <label for="password">Password</label>
            <input type="password" id="password" name="password" placeholder="Password" required>

            <button type="submit">Register</button>
            <!-- Di register.php, tepat sebelum </form> -->
            <p style="text-align:center; margin-top:8px;">
            Sudah punya akun? <a href="login.php">Login di sini</a>
            </p>
        </form>
    </div>
</body>
</html>
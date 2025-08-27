<?php
// login.php
session_start();
include 'db.php';

$loginError = '';
$attemptsLeft = 0;

// Konfigurasi batas percobaan
$MAX_ATTEMPTS = 5;
$WARNING_THRESHOLD = 3; // Tampilkan peringatan setelah 3 kegagalan

if (!isset($_SESSION['login_attempts'])) {
    $_SESSION['login_attempts'] = 0;
}
if (!isset($_SESSION['last_login_time'])) {
    $_SESSION['last_login_time'] = time();
}

// Reset hitungannya jika sudah lama tidak ada percobaan
if (time() - $_SESSION['last_login_time'] > 15 * 60) {
    $_SESSION['login_attempts'] = 0;
}
$_SESSION['last_login_time'] = time();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $input = $_POST['input'];      // bisa berupa username atau email
    $password = $_POST['password'];

    // Cek batas percobaan
    if ($_SESSION['login_attempts'] >= $MAX_ATTEMPTS) {
        $loginError = 'Terlalu banyak percobaan login. Silakan coba lagi nanti.';
    } else {
        // Ambil data user dari database berdasarkan username atau email
        $stmt = $conn->prepare('SELECT username, email, password FROM users WHERE username = ? OR email = ? LIMIT 1');
        $stmt->bind_param('ss', $input, $input);
        $stmt->execute();
        $stmt->store_result();

        if ($stmt->num_rows > 0) {
            $stmt->bind_result($dbUsername, $dbEmail, $hashedPassword);
            $stmt->fetch();

            if (password_verify($password, $hashedPassword)) {
                // Login berhasil
                $_SESSION['logged_in_user'] = $dbUsername;
                // Reset attempts on successful login
                $_SESSION['login_attempts'] = 0;
                header('Location: dashboard.php');
                exit;
            } else {
                // Password salah
                $_SESSION['login_attempts'] += 1;
                $attemptsLeft = max(0, $MAX_ATTEMPTS - $_SESSION['login_attempts']);
                $loginError = 'Password salah!';

                // Peringatan khusus jika telah mencapai threshold tertentu
                if ($_SESSION['login_attempts'] >= $WARNING_THRESHOLD && $_SESSION['login_attempts'] < $MAX_ATTEMPTS) {
                    // Anda bisa menampilkan peringatan yang lebih jelas di UI
                    // Misal mengubah pesan atau menambahkan info di bawah sini
                    $loginError .= ' (peringatan: beberapa upaya gagal telah dicatat.)';
                }
            }
        } else {
            // User/email tidak ditemukan
            $_SESSION['login_attempts'] += 1;
            $attemptsLeft = max(0, $MAX_ATTEMPTS - $_SESSION['login_attempts']);
            $loginError = 'Username atau Email tidak ditemukan!';

            if ($_SESSION['login_attempts'] >= $WARNING_THRESHOLD && $_SESSION['login_attempts'] < $MAX_ATTEMPTS) {
                $loginError .= ' Jangan menyerah, pastikan kota Anda benar.';
            }
        }
        $stmt->close();
    }
}
?>

<!DOCTYPE html>
<html>
<head>
    <title>Login</title>
    <style>
        body { font-family: Arial, sans-serif; background: #f2f2f2; }
        .login-container {
            background: #fff;
            padding: 30px;
            margin: 80px auto;
            width: 350px;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }
        .login-container h2 { text-align: center; margin-bottom: 20px; }
        .login-container input[type="text"],
        .login-container input[type="password"] {
            width: 100%; padding: 10px; margin: 8px 0 16px 0; border: 1px solid #ccc; border-radius: 4px;
        }
        .login-container button {
            width: 100%; padding: 10px; background: #007bff; color: #fff; border: none; border-radius: 4px;
            cursor: pointer;
        }
        .login-container button:hover { background: #0056b3; }
        .error { color: red; text-align: center; margin-bottom: 10px; }
        .hint { font-size: 12px; color: #555; text-align: center; margin-top: 8px; }
        .success { color: green; text-align: center; margin-bottom: 10px; }
    </style>
</head>
<body>
    <div class="login-container">
        <h2>Login</h2>
        <?php if ($loginError): ?>
            <div class="error"><?= htmlspecialchars($loginError) ?></div>
        <?php endif; ?>
        <?php if ($_SESSION['login_attempts'] >= $MAX_ATTEMPTS): ?>
            <div class="hint">Anda telah mencapai batas percobaan. Silakan tunggu beberapa saat.</div>
        <?php endif; ?>
        <form method="POST" action="">
            <input type="text" name="input" placeholder="Username atau Email" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Login</button>
        </form>
        <p style="text-align:center; margin-top:8px;">
        Belum punya akun? <a href="register.php">Daftar di sini</a>
        </p>
    </div>
</body>
</html>
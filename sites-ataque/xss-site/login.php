<?php
session_start();
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Login simples para demonstração
    $username = $_POST['username'];
    $password = $_POST['password'];
    
    // Credenciais fixas para teste
    if ($username === 'admin' && $password === 'admin123') {
        $_SESSION['user'] = $username;
        $_SESSION['loggedin'] = true;
        header('Location: dashboard.php');
        exit;
    } else {
        $error = "Credenciais inválidas!";
    }
}
?>

<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - PolyTools XSS</title>
    <link rel="stylesheet" href="css/style.css">
</head>
<body>
    <div class="container">
        <div class="login-container">
            <div class="login-header">
                <h1>🔧 PolyTools</h1>
                <p>Laboratório XSS - Login</p>
            </div>
            
            <?php if (isset($error)): ?>
                <div class="error-message">
                    <?php echo $error; ?>
                </div>
            <?php endif; ?>
            
            <form method="POST" class="login-form">
                <div class="form-group">
                    <label for="username">Usuário:</label>
                    <input type="text" id="username" name="username" value="admin" required>
                </div>
                
                <div class="form-group">
                    <label for="password">Senha:</label>
                    <input type="password" id="password" name="password" value="admin123" required>
                </div>
                
                <button type="submit" class="btn-submit">Entrar</button>
            </form>
            
            <div class="demo-credentials">
                <p><strong>Credenciais de teste:</strong></p>
                <p>Usuário: <code>admin</code></p>
                <p>Senha: <code>admin123</code></p>
            </div>
        </div>
    </div>
</body>
</html>

<?php
session_start();
include 'includes/config.php';

// Credenciais vulneráveis (para demonstração)
$valid_username = "admin";
$valid_password = "123456";

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = $_POST['username'];
    $password = $_POST['password'];
    
    // Vulnerabilidade: Sem limite de tentativas, sem CAPTCHA, sem delay
    if ($username === $valid_username && $password === $valid_password) {
        $_SESSION['loggedin'] = true;
        $_SESSION['username'] = $username;
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
    <title>Login - PolyTools</title>
    <link rel="stylesheet" href="css/style.css">
</head>
<body>
    <div class="container">
        <div class="login-container">
            <div class="login-header">
                <h1>🔧 PolyTools</h1>
                <p>Área de Login</p>
            </div>
            
            <?php if (isset($error)): ?>
                <div class="error-message" id="errorMessage">
                    <?php echo $error; ?>
                </div>
            <?php endif; ?>
            
            <form method="POST" action="login.php" class="login-form">
                <div class="form-group">
                    <label for="username">Usuário:</label>
                    <input type="text" id="username" name="username" required 
                           placeholder="Digite o usuário">
                </div>
                
                <div class="form-group">
                    <label for="password">Senha:</label>
                    <input type="password" id="password" name="password" required 
                           placeholder="Digite a senha">
                </div>
                
                <button type="submit" class="btn-submit">Entrar</button>
            </form>
            
            <div class="login-info">
                <p><strong>Laboratório de Segurança</strong></p>
                <p>Este sistema é intencionalmente vulnerável para fins educacionais</p>
            </div>
        </div>
    </div>
    
    <script src="js/animations.js"></script>
</body>
</html>

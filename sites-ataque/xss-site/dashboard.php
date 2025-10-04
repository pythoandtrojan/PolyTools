<?php
session_start();
if (!isset($_SESSION['loggedin']) || $_SESSION['loggedin'] !== true) {
    header('Location: login.php');
    exit;
}

// Vulnerabilidade: Refletir parâmetros sem sanitização
$message = $_GET['message'] ?? 'Bem-vindo ao Dashboard';
$status = $_GET['status'] ?? 'info';
?>

<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard - PolyTools XSS</title>
    <link rel="stylesheet" href="css/style.css">
</head>
<body>
    <div class="container">
        <header>
            <div class="logo">
                <h1>🔧 PolyTools</h1>
                <p>Dashboard - Laboratório XSS</p>
            </div>
            <nav>
                <a href="logout.php" class="btn-logout">Sair</a>
            </nav>
        </header>

        <main>
            <!-- VULNERABILIDADE: XSS Refletido -->
            <div class="alert alert-<?php echo $status; ?>">
                <h3>Mensagem do Sistema:</h3>
                <div id="systemMessage">
                    <?php echo $message; // VULNERÁVEL - sem htmlspecialchars ?>
                </div>
            </div>

            <div class="dashboard-grid">
                <div class="dashboard-card">
                    <h3>Teste XSS Refletido</h3>
                    <p>Adicione parâmetros na URL para testar XSS:</p>
                    <div class="xss-examples">
                        <p><strong>Exemplos:</strong></p>
                        <code>?message=&lt;script&gt;alert('XSS')&lt;/script&gt;</code><br>
                        <code>?message=&lt;img src=x onerror=alert('XSS')&gt;</code>
                    </div>
                </div>

                <div class="dashboard-card">
                    <h3>Áreas de Teste</h3>
                    <ul class="test-links">
                        <li><a href="search.php">🔍 Busca Vulnerável</a></li>
                        <li><a href="comments.php">💬 Comentários XSS</a></li>
                        <li><a href="profile.php">👤 Perfil Vulnerável</a></li>
                    </ul>
                </div>
            </div>
        </main>
    </div>
</body>
</html>

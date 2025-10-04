<?php
session_start();
if (!isset($_SESSION['loggedin']) || $_SESSION['loggedin'] !== true) {
    header('Location: login.php');
    exit;
}
?>

<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard - PolyTools</title>
    <link rel="stylesheet" href="css/style.css">
</head>
<body>
    <div class="container">
        <header>
            <div class="logo">
                <h1>🔧 PolyTools</h1>
                <p>Dashboard - Ferramentas Profissionais</p>
            </div>
            <nav>
                <a href="logout.php" class="btn-logout">Sair</a>
            </nav>
        </header>
        
        <main>
            <div class="success-section" id="successSection">
                <div class="success-icon">🎉</div>
                <h2>Parabéns!</h2>
                <p>Você conseguiu acessar o sistema PolyTools!</p>
                <p class="success-details">Login bem-sucedido como: <strong><?php echo $_SESSION['username']; ?></strong></p>
                
                <div class="tools-grid">
                    <div class="tool-card">
                        <h3>Ferramenta 1</h3>
                        <p>Scanner de Rede</p>
                    </div>
                    <div class="tool-card">
                        <h3>Ferramenta 2</h3>
                        <p>Analisador de Segurança</p>
                    </div>
                    <div class="tool-card">
                        <h3>Ferramenta 3</h3>
                        <p>Monitor de Sistema</p>
                    </div>
                </div>
            </div>
        </main>
    </div>
    
    <script src="js/animations.js"></script>
</body>
</html>

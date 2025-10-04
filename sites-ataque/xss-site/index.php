<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PolyTools - Laboratório XSS</title>
    <link rel="stylesheet" href="css/style.css">
</head>
<body>
    <div class="container">
        <header>
            <div class="logo">
                <h1>🔧 PolyTools</h1>
                <p>Laboratório de Segurança - XSS</p>
            </div>
        </header>
        
        <main>
            <div class="hero-section">
                <h2>Laboratório XSS PolyTools</h2>
                <p>Teste vulnerabilidades de Cross-Site Scripting em um ambiente controlado</p>
                
                <div class="features-grid">
                    <div class="feature-card">
                        <h3>🔍 Busca Vulnerável</h3>
                        <p>Campo de busca sem sanitização</p>
                        <a href="search.php" class="btn-feature">Testar</a>
                    </div>
                    
                    <div class="feature-card">
                        <h3>💬 Comentários</h3>
                        <p>Sistema de comentários vulnerável</p>
                        <a href="comments.php" class="btn-feature">Testar</a>
                    </div>
                    
                    <div class="feature-card">
                        <h3>👤 Perfil</h3>
                        <p>Perfil de usuário com XSS</p>
                        <a href="profile.php" class="btn-feature">Testar</a>
                    </div>
                </div>
                
                <div class="warning-box">
                    <h4>⚠️ AVISO DE SEGURANÇA</h4>
                    <p>Este é um laboratório educativo com vulnerabilidades intencionais.</p>
                    <p>Nunca implemente essas práticas em produção!</p>
                </div>
            </div>
        </main>
    </div>
    
    <script src="js/animations.js"></script>
</body>
</html>

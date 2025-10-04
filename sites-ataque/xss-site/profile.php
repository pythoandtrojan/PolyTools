<?php
session_start();
if (!isset($_SESSION['loggedin']) || $_SESSION['loggedin'] !== true) {
    header('Location: login.php');
    exit;
}

// Perfil do usuário (simulado)
if (!isset($_SESSION['profile'])) {
    $_SESSION['profile'] = [
        'name' => 'Administrador',
        'bio' => 'Usuário do sistema PolyTools',
        'website' => 'https://polytools.com'
    ];
}

// Atualizar perfil
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $_SESSION['profile']['name'] = $_POST['name']; // VULNERÁVEL
    $_SESSION['profile']['bio'] = $_POST['bio']; // VULNERÁVEL
    $_SESSION['profile']['website'] = $_POST['website']; // VULNERÁVEL
    $success = "Perfil atualizado com sucesso!";
}

$profile = $_SESSION['profile'];
?>

<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Perfil - PolyTools XSS</title>
    <link rel="stylesheet" href="css/style.css">
</head>
<body>
    <div class="container">
        <header>
            <div class="logo">
                <h1>🔧 PolyTools</h1>
                <p>Perfil do Usuário - Laboratório XSS</p>
            </div>
            <nav>
                <a href="dashboard.php" class="btn-back">Voltar</a>
            </nav>
        </header>

        <main>
            <div class="profile-section">
                <div class="profile-header">
                    <h2>👤 Perfil do Usuário</h2>
                    <p class="warning">⚠️ VULNERÁVEL a XSS Armazenado</p>
                </div>

                <div class="profile-display">
                    <h3>Seu Perfil:</h3>
                    <div class="profile-info">
                        <p><strong>Nome:</strong> <span id="profileName"><?php echo $profile['name']; ?></span></p>
                        <p><strong>Bio:</strong> <span id="profileBio"><?php echo $profile['bio']; ?></span></p>
                        <p><strong>Website:</strong> <span id="profileWebsite"><?php echo $profile['website']; ?></span></p>
                    </div>
                </div>

                <div class="profile-edit">
                    <h3>Editar Perfil:</h3>
                    
                    <?php if (isset($success)): ?>
                        <div class="success-message"><?php echo $success; ?></div>
                    <?php endif; ?>

                    <form method="POST">
                        <div class="form-group">
                            <label for="name">Nome:</label>
                            <input type="text" id="name" name="name" value="<?php echo htmlspecialchars($profile['name']); ?>" required>
                        </div>
                        
                        <div class="form-group">
                            <label for="bio">Biografia:</label>
                            <textarea id="bio" name="bio" rows="4"><?php echo htmlspecialchars($profile['bio']); ?></textarea>
                        </div>
                        
                        <div class="form-group">
                            <label for="website">Website:</label>
                            <input type="url" id="website" name="website" value="<?php echo htmlspecialchars($profile['website']); ?>">
                        </div>
                        
                        <button type="submit" class="btn-submit">Atualizar Perfil</button>
                    </form>
                </div>

                <div class="dom-xss-section">
                    <h3>🔍 Teste DOM-Based XSS</h3>
                    <p>Digite algo para ser exibido via JavaScript:</p>
                    <input type="text" id="domInput" placeholder="Teste DOM XSS...">
                    <button onclick="displayDOMInput()">Exibir</button>
                    <div id="domOutput"></div>
                </div>
            </div>
        </main>
    </div>

    <script>
        // VULNERABILIDADE: DOM-Based XSS
        function displayDOMInput() {
            const input = document.getElementById('domInput').value;
            const output = document.getElementById('domOutput');
            // VULNERÁVEL - innerHTML sem sanitização
            output.innerHTML = '<p>Você digitou: ' + input + '</p>';
        }

        // VULNERABILIDADE: XSS via URL parameters
        const urlParams = new URLSearchParams(window.location.search);
        const welcomeMessage = urlParams.get('welcome');
        if (welcomeMessage) {
            document.write('<div class="url-message">' + welcomeMessage + '</div>');
        }
    </script>
</body>
</html>

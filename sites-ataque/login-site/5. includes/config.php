<?php
// Configurações básicas (vulneráveis)
error_reporting(0); // Esconde erros (má prática)

// Conexão com banco de dados (simulada)
$db_host = "localhost";
$db_user = "root";
$db_pass = "";
$db_name = "polytools";

// Função vulnerável de login (para demonstração)
function vulnerable_login($username, $password) {
    // Simulação de verificação sem segurança
    return true;
}
?>

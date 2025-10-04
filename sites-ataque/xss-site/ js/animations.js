// Animações para o PolyTools XSS
document.addEventListener('DOMContentLoaded', function() {
    // Efeito de digitação para títulos
    const animatedTitles = document.querySelectorAll('.hero-section h2');
    
    animatedTitles.forEach(title => {
        const text = title.textContent;
        title.textContent = '';
        let i = 0;
        
        function typeWriter() {
            if (i < text.length) {
                title.textContent += text.charAt(i);
                i++;
                setTimeout(typeWriter, 100);
            }
        }
        
        setTimeout(typeWriter, 1000);
    });

    // Efeito de entrada para cards
    const cards = document.querySelectorAll('.feature-card, .dashboard-card');
    
    cards.forEach((card, index) => {
        card.style.opacity = '0';
        card.style.transform = 'translateY(30px)';
        
        setTimeout(() => {
            card.style.transition = 'all 0.6s ease';
            card.style.opacity = '1';
            card.style.transform = 'translateY(0)';
        }, index * 200);
    });

    // Efeito de foco em inputs vulneráveis
    const vulnerableInputs = document.querySelectorAll('input[name="q"], textarea[name="comment"]');
    
    vulnerableInputs.forEach(input => {
        input.addEventListener('focus', function() {
            this.style.borderColor = '#dc3545';
            this.style.boxShadow = '0 0 0 3px rgba(220, 53, 69, 0.1)';
        });
        
        input.addEventListener('blur', function() {
            this.style.borderColor = '#ddd';
            this.style.boxShadow = 'none';
        });
    });

    // Demonstrar vulnerabilidade XSS de forma educativa
    const demoXSS = document.getElementById('demoXSS');
    if (demoXSS) {
        setTimeout(() => {
            demoXSS.innerHTML = '<p style="color: #dc3545; font-weight: bold;">⚠️ Esta área é vulnerável a XSS!</p>';
        }, 3000);
    }

    // Efeito de pulso para avisos de segurança
    const warnings = document.querySelectorAll('.warning');
    
    warnings.forEach(warning => {
        setInterval(() => {
            warning.style.transform = warning.style.transform === 'scale(1.05)' ? 'scale(1)' : 'scale(1.05)';
        }, 1000);
    });

    // Tooltip para payloads XSS
    const payloadCodes = document.querySelectorAll('.xss-tips code, .payload-card code');
    
    payloadCodes.forEach(code => {
        code.title = 'Clique para copiar';
        code.style.cursor = 'pointer';
        
        code.addEventListener('click', function() {
            navigator.clipboard.writeText(this.textContent).then(() => {
                const originalText = this.textContent;
                this.textContent = '✅ Copiado!';
                this.style.background = '#d4edda';
                
                setTimeout(() => {
                    this.textContent = originalText;
                    this.style.background = '';
                }, 2000);
            });
        });
    });

    // Simular ataque XSS educativo (apenas demonstração)
    function educationalXSSDemo() {
    console.log('🔓 Laboratório XSS PolyTools - Ambiente Educacional');
    console.log('Vulnerabilidades disponíveis:');
    console.log('1. XSS Refletido (search.php, dashboard.php)');
    console.log('2. XSS Armazenado (comments.php, profile.php)');
    console.log('3. DOM-Based XSS (profile.php)');
    }
    
    educationalXSSDemo();
});

// Função para demonstrar XSS DOM-Based
function demonstrateDOMXSS() {
    const userInput = prompt('Digite um payload XSS para teste DOM-Based:');
    if (userInput) {
        const demoElement = document.createElement('div');
        demoElement.innerHTML = '<p>Resultado: ' + userInput + '</p>';
        document.body.appendChild(demoElement);
        
        alert('Payload executado! Verifique o console para detalhes.');
        console.log('Payload executado via innerHTML:', userInput);
    }
}

// Exemplo de payloads XSS para teste
const xssPayloads = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert('XSS')>",
    "<body onload=alert('XSS')>",
    "<iframe src=javascript:alert('XSS')>",
    "<a href=javascript:alert('XSS')>Clique</a>"
];

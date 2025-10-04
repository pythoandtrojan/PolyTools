// Animations for PolyTools
document.addEventListener('DOMContentLoaded', function() {
    // Input focus animations
    const inputs = document.querySelectorAll('input[type="text"], input[type="password"]');
    
    inputs.forEach(input => {
        input.addEventListener('focus', function() {
            this.parentElement.classList.add('focused');
        });
        
        input.addEventListener('blur', function() {
            if (!this.value) {
                this.parentElement.classList.remove('focused');
            }
        });
    });

    // Button click animations
    const buttons = document.querySelectorAll('button, .btn-login, .btn-submit');
    
    buttons.forEach(button => {
        button.addEventListener('click', function(e) {
            // Create ripple effect
            const ripple = document.createElement('span');
            const rect = this.getBoundingClientRect();
            const size = Math.max(rect.width, rect.height);
            const x = e.clientX - rect.left - size / 2;
            const y = e.clientY - rect.top - size / 2;
            
            ripple.style.width = ripple.style.height = size + 'px';
            ripple.style.left = x + 'px';
            ripple.style.top = y + 'px';
            ripple.classList.add('ripple');
            
            this.appendChild(ripple);
            
            // Remove ripple after animation
            setTimeout(() => {
                ripple.remove();
            }, 600);
        });
    });

    // Error message auto-hide
    const errorMessage = document.getElementById('errorMessage');
    if (errorMessage) {
        setTimeout(() => {
            errorMessage.style.opacity = '0';
            errorMessage.style.transform = 'translateX(20px)';
            setTimeout(() => {
                errorMessage.remove();
            }, 500);
        }, 5000);
    }

    // Success section particles
    const successSection = document.getElementById('successSection');
    if (successSection) {
        createParticles();
    }

    // Form submission loading state
    const forms = document.querySelectorAll('form');
    forms.forEach(form => {
        form.addEventListener('submit', function() {
            const submitBtn = this.querySelector('button[type="submit"]');
            if (submitBtn) {
                submitBtn.innerHTML = 'Processando...';
                submitBtn.disabled = true;
            }
        });
    });
});

// Particle effect for success page
function createParticles() {
    const colors = ['#667eea', '#764ba2', '#f093fb', '#ffd89b'];
    
    for (let i = 0; i < 15; i++) {
        setTimeout(() => {
            createParticle();
        }, i * 200);
    }
}

function createParticle() {
    const particle = document.createElement('div');
    particle.style.cssText = `
        position: fixed;
        width: 10px;
        height: 10px;
        background: ${getRandomColor()};
        border-radius: 50%;
        pointer-events: none;
        z-index: 1000;
        animation: floatParticle 3s ease-in-out forwards;
    `;
    
    particle.style.left = Math.random() * 100 + 'vw';
    particle.style.top = '100vh';
    
    document.body.appendChild(particle);
    
    setTimeout(() => {
        particle.remove();
    }, 3000);
}

function getRandomColor() {
    const colors = ['#667eea', '#764ba2', '#27ae60', '#e74c3c', '#f39c12', '#9b59b6'];
    return colors[Math.floor(Math.random() * colors.length)];
}

// Add CSS for ripple effect and particles
const style = document.createElement('style');
style.textContent = `
    .ripple {
        position: absolute;
        border-radius: 50%;
        background: rgba(255, 255, 255, 0.6);
        transform: scale(0);
        animation: ripple-animation 0.6s linear;
    }
    
    @keyframes ripple-animation {
        to {
            transform: scale(4);
            opacity: 0;
        }
    }
    
    @keyframes floatParticle {
        0% {
            transform: translateY(0) rotate(0deg);
            opacity: 1;
        }
        100% {
            transform: translateY(-100vh) rotate(360deg);
            opacity: 0;
        }
    }
    
    .form-group.focused label {
        color: #667eea;
        transform: translateY(-5px);
        font-size: 0.9em;
    }
`;
document.head.appendChild(style);

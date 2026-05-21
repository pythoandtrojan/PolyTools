#!/usr/bin/env bash
#
# Script de Instalação de Dependências para Ferramentas de Segurança
# Autor: Security Toolbox
# Descrição: Instala todas as dependências necessárias para ferramentas de pentest
#

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configurações
TIMEOUT=300
PIP_TIMEOUT=300

# Banner ASCII Art
print_banner() {
    clear
    echo -e "${GREEN}"
    cat << "EOF"
██╗███╗   ██╗███████╗████████╗ █████╗ ██╗     ██╗     
██║████╗  ██║██╔════╝╚══██╔══╝██╔══██╗██║     ██║     
██║██╔██╗ ██║███████╗   ██║   ███████║██║     ██║     
██║██║╚██╗██║╚════██║   ██║   ██╔══██║██║     ██║     
██║██║ ╚████║███████║   ██║   ██║  ██║███████╗███████╗
╚═╝╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚══════╝
EOF
    echo -e "${NC}"
    echo -e "${CYAN}📦 Iniciando instalação de dependências...${NC}"
    echo -e "${YELLOW}⏳ Isso pode levar alguns minutos...${NC}\n"
}

# Função para verificar se comando existe
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Função para verificar versão do Python
check_python() {
    if command_exists python3; then
        PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
        PYTHON_MAJOR=$(echo $PYTHON_VERSION | cut -d. -f1)
        PYTHON_MINOR=$(echo $PYTHON_VERSION | cut -d. -f2)
        
        if [ "$PYTHON_MAJOR" -ge 3 ] && [ "$PYTHON_MINOR" -ge 6 ]; then
            echo -e "${GREEN}✅ Python $PYTHON_VERSION detectado${NC}"
            return 0
        else
            echo -e "${RED}❌ Python 3.6 ou superior é necessário! (Detectado: $PYTHON_VERSION)${NC}"
            return 1
        fi
    else
        echo -e "${RED}❌ Python 3 não encontrado!${NC}"
        return 1
    fi
}

# Verifica se pip está instalado
check_pip() {
    if command_exists pip3; then
        return 0
    else
        return 1
    fi
}

# Instala pip se necessário
install_pip() {
    echo -e "${BLUE}🔧 Instalando pip...${NC}"
    
    if command_exists python3; then
        python3 -m ensurepip --upgrade 2>/dev/null
        python3 -m pip install --upgrade pip 2>/dev/null
        if check_pip; then
            echo -e "${GREEN}✅ Pip instalado com sucesso!${NC}"
            return 0
        fi
    fi
    
    echo -e "${RED}❌ Falha ao instalar pip!${NC}"
    return 1
}

# Executa comando com timeout
run_command() {
    local description="$1"
    shift
    local cmd=("$@")
    
    echo -e "${CYAN}📥 $description...${NC}"
    
    # Executa com timeout
    timeout $TIMEOUT "${cmd[@]}" > /tmp/install_log.txt 2>&1
    local exit_code=$?
    
    if [ $exit_code -eq 0 ]; then
        echo -e "${GREEN}✅ $description - Concluído!${NC}"
        return 0
    elif [ $exit_code -eq 124 ]; then
        echo -e "${RED}⏰ Timeout ao executar $description!${NC}"
        return 1
    else
        echo -e "${RED}❌ Erro ao executar $description!${NC}"
        local error_msg=$(tail -n 3 /tmp/install_log.txt 2>/dev/null)
        if [ -n "$error_msg" ]; then
            echo -e "   Detalhes: ${error_msg:0:200}..."
        fi
        return 1
    fi
}

# Instala pacote Python
install_python_package() {
    local package="$1"
    local progress="$2"
    
    echo -e "${CYAN}📥 $progress Instalando $package...${NC}"
    
    timeout $PIP_TIMEOUT pip3 install --upgrade "$package" > /tmp/pip_log.txt 2>&1
    
    if [ $? -ne 0 ]; then
        echo -e "${YELLOW}   Tentando instalação alternativa para $package...${NC}"
        timeout $PIP_TIMEOUT pip3 install "$package" > /tmp/pip_log.txt 2>&1
        if [ $? -ne 0 ]; then
            echo -e "${RED}❌ Falha ao instalar $package${NC}"
            return 1
        fi
    fi
    
    echo -e "${GREEN}✅ $package instalado!${NC}"
    return 0
}

# Instala dependências principais
install_dependencies() {
    echo -e "${CYAN}📦 Instalando dependências...${NC}\n"
    
    local total=0
    local installed=0
    
    # Contar total de pacotes
    for category in "${!categories[@]}"; do
        for package in ${categories[$category]}; do
            ((total++))
        done
    done
    
    echo -e "${YELLOW}Total de pacotes a instalar: $total${NC}\n"
    
    # Instalar categorias
    for category in "Interface e Cores" "OSINT e Reconhecimento" "Requests e Web Scraping" \
                    "Utilitários Gerais" "Criptografia e Segurança" "Banco de Dados e Cache" \
                    "Ferramentas de Rede" "Processamento de Imagens" "Análise de Dados" \
                    "Desenvolvimento Web"; do
        
        echo -e "\n${BLUE}📊 $category${NC}"
        echo -e "${BLUE}==================================================${NC}"
        
        case $category in
            "Interface e Cores")
                packages=("rich" "colorama" "pyfiglet" "termcolor" "tqdm" "alive-progress")
                ;;
            "OSINT e Reconhecimento")
                packages=("holehe" "sherlock-project" "maigret" "social-analyzer" 
                         "reverse-geocoder" "folium" "instaloader")
                ;;
            "Requests e Web Scraping")
                packages=("requests" "beautifulsoup4" "lxml" "selenium" "cloudscraper" 
                         "httpx" "aiohttp")
                ;;
            "Utilitários Gerais")
                packages=("fake-useragent" "python-dotenv" "click" "psutil" 
                         "python-dateutil" "watchdog")
                ;;
            "Criptografia e Segurança")
                packages=("cryptography" "pycryptodome" "paramiko" "scapy" "impacket")
                ;;
            "Banco de Dados e Cache")
                packages=("redis" "pymongo" "sqlalchemy" "psycopg2-binary")
                ;;
            "Ferramentas de Rede")
                packages=("pysocks" "netifaces" "scapy")
                ;;
            "Processamento de Imagens")
                packages=("pillow" "opencv-python-headless" "imageio" "matplotlib")
                ;;
            "Análise de Dados")
                packages=("pandas" "numpy" "scipy" "matplotlib" "seaborn" "jupyter")
                ;;
            "Desenvolvimento Web")
                packages=("flask" "flask-socketio" "jinja2" "werkzeug")
                ;;
        esac
        
        for package in "${packages[@]}"; do
            ((installed++))
            local progress="[$installed/$total]"
            
            # Tratamento especial para pacotes problemáticos
            if [ "$package" = "impacket" ]; then
                echo -e "${YELLOW}⚠️  $progress $package - Instalação especial necessária${NC}"
                run_command "$progress Instalando $package (método especial)" pip3 install impacket
            else
                install_python_package "$package" "$progress"
            fi
            
            sleep 0.5
        done
    done
    
    echo "$installed"
}

# Instala ferramentas específicas
install_specific_tools() {
    echo -e "\n${BLUE}🔧 Instalando ferramentas específicas...${NC}"
    echo -e "${BLUE}==================================================${NC}"
    
    # Ferramentas que precisam de instalação especial
    run_command "Instalando Sherlock" pip3 install sherlock-project
    run_command "Instalando Holehe" pip3 install holehe
    run_command "Instalando Maigret" pip3 install maigret
    run_command "Instalando Social Analyzer" pip3 install social-analyzer
    run_command "Instalando Reverse Geocoder" pip3 install reverse-geocoder
    run_command "Instalando Folium" pip3 install folium
    run_command "Instalando Flask-SocketIO" pip3 install flask-socketio
}

# Instala dependências do sistema
install_system_specific() {
    local system=$(uname -s | tr '[:upper:]' '[:lower:]')
    
    echo -e "\n${BLUE}💻 Instalando dependências específicas do $system...${NC}"
    echo -e "${BLUE}==================================================${NC}"
    
    case $system in
        linux)
            if command_exists apt; then
                echo -e "${YELLOW}Detectado Debian/Ubuntu${NC}"
                run_command "Atualizando repositórios" sudo apt update
                
                local linux_packages=(
                    "python3-dev" "build-essential" "libssl-dev"
                    "libffi-dev" "libxml2-dev" "libxslt1-dev"
                    "libjpeg-dev" "zlib1g-dev" "libnetfilter-queue-dev"
                )
                
                for pkg in "${linux_packages[@]}"; do
                    run_command "Instalando $pkg" sudo apt install -y "$pkg"
                done
            elif command_exists yum; then
                echo -e "${YELLOW}Detectado RedHat/CentOS${NC}"
                local linux_packages=(
                    "python3-devel" "gcc" "openssl-devel"
                    "libffi-devel" "libxml2-devel" "libxslt-devel"
                )
                
                for pkg in "${linux_packages[@]}"; do
                    run_command "Instalando $pkg" sudo yum install -y "$pkg"
                done
            fi
            ;;
        darwin)
            if command_exists brew; then
                run_command "Instalando dependências via Homebrew" brew install libmagic geoip imagesnap
            else
                echo -e "${YELLOW}⚠️ Homebrew não encontrado. Instale manualmente as dependências.${NC}"
            fi
            ;;
        mingw*|cygwin*|msys*)
            echo -e "${YELLOW}📝 No Windows, certifique-se de ter o Microsoft C++ Build Tools instalado${NC}"
            ;;
    esac
}

# Verifica instalações
post_installation_check() {
    echo -e "\n${BLUE}🔍 Verificando instalações...${NC}"
    echo -e "${BLUE}==================================================${NC}"
    
    local check_packages=(
        "requests" "rich" "colorama" "bs4" "selenium"
        "fake-useragent" "cryptography" "pandas"
        "flask" "pillow" "psutil" "numpy"
    )
    
    for package in "${check_packages[@]}"; do
        if python3 -c "import $package" 2>/dev/null; then
            echo -e "${GREEN}✅ $package - OK${NC}"
        else
            echo -e "${RED}❌ $package - Falha na verificação${NC}"
        fi
    done
}

# Cria arquivo requirements.txt
create_requirements_file() {
    cat > requirements_security.txt << 'EOF'
# Dependências para Ferramentas de Segurança
# Gerado automaticamente pelo script de instalação

# Interface e Cores
rich>=13.0.0
colorama>=0.4.6
pyfiglet>=0.8.post1
termcolor>=2.3.0
tqdm>=4.65.0
alive-progress>=3.1.4

# OSINT e Reconhecimento
holehe>=0.4.5
sherlock-project>=0.14.0
social-analyzer>=0.45
maigret>=0.5.0
reverse-geocoder>=1.5.1
folium>=0.14.0

# Web Scraping
requests>=2.31.0
beautifulsoup4>=4.12.2
selenium>=4.15.0
cloudscraper>=1.2.71
httpx>=0.25.2
aiohttp>=3.9.1

# Utilitários Gerais
fake-useragent>=1.4.0
python-dotenv>=1.0.0
click>=8.1.7
psutil>=5.9.6
python-dateutil>=2.8.2

# Segurança e Criptografia
cryptography>=41.0.7
pycryptodome>=3.19.0
paramiko>=3.3.1
scapy>=2.5.0

# Análise de Dados
pandas>=2.1.3
numpy>=1.25.2
matplotlib>=3.8.2
seaborn>=0.13.0

# Desenvolvimento Web
flask>=3.0.0
flask-socketio>=5.3.6
jinja2>=3.1.2

# Processamento de Imagens
pillow>=10.1.0
opencv-python-headless>=4.8.1

# Banco de Dados
sqlalchemy>=2.0.23
pymongo>=4.5.0
redis>=5.0.1
EOF
    
    echo -e "${GREEN}📄 Arquivo requirements_security.txt criado!${NC}"
}

# Função principal
main() {
    # Exibir banner
    print_banner
    
    # Verificar Python
    if ! check_python; then
        exit 1
    fi
    
    # Verificar e instalar pip
    if ! check_pip; then
        if ! install_pip; then
            echo -e "${RED}❌ Não é possível continuar sem pip!${NC}"
            exit 1
        fi
    fi
    
    # Atualizar pip
    run_command "Atualizando pip" pip3 install --upgrade pip
    
    # Instalar dependências
    total_installed=$(install_dependencies)
    
    # Instalar ferramentas específicas
    install_specific_tools
    
    # Instalar dependências do sistema
    install_system_specific
    
    # Verificação final
    post_installation_check
    
    # Criar arquivo de requirements
    create_requirements_file
    
    # Mensagem final
    echo -e "\n${GREEN}============================================================${NC}"
    echo -e "${GREEN}🎉 INSTALAÇÃO CONCLUÍDA!${NC}"
    echo -e "${GREEN}============================================================${NC}"
    echo -e "${YELLOW}📦 Total de pacotes processados: $total_installed${NC}"
    echo -e "\n${CYAN}📚 Principais categorias instaladas:${NC}"
    echo "   • Ferramentas de OSINT (holehe, sherlock, maigret, etc.)"
    echo "   • Bibliotecas de interface (rich, colorama, etc.)"
    echo "   • Ferramentas de rede e segurança (scapy, cryptography)"
    echo "   • Utilitários de scraping e automação (selenium, requests)"
    echo "   • Análise de dados (pandas, numpy, matplotlib)"
    echo "   • Desenvolvimento web (flask, flask-socketio)"
    echo "   • Processamento de imagens (pillow, opencv)"
    echo "   • Sistema e utilitários (psutil, socket)"
    echo -e "\n${YELLOW}⚠️  Algumas ferramentas podem requer configuração adicional.${NC}"
    echo -e "${CYAN}📖 Consulte a documentação de cada ferramenta para uso correto.${NC}"
    echo -e "${GREEN}📄 Arquivo requirements_security.txt gerado para uso futuro.${NC}"
    echo -e "${GREEN}============================================================${NC}"
}

# Executar script
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    trap 'echo -e "\n\n${RED}❌ Instalação interrompida pelo usuário!${NC}"; exit 1' INT
    main "$@"
fi

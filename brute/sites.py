#!/bin/bash

# Configurações globais
declare -A CONFIG=(
    [WORDLIST_COMMON]="/usr/share/dirb/wordlists/common.txt"
    [WORDLIST_BIG]="/usr/share/dirb/wordlists/big.txt"
    [DEFAULT_OUTPUT_DIR]="$(pwd)/dirb_scans"
    [TIMEOUT]=10
)

# Cores para o terminal
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Verificar dependências
check_dependencies() {
    local missing=()
    for cmd in dirb curl; do
        if ! command -v $cmd &> /dev/null; then
            missing+=("$cmd")
        fi
    done
    
    if [ ${#missing[@]} -gt 0 ]; then
        echo -e "${RED}[ERRO] Dependências ausentes:${NC}"
        for cmd in "${missing[@]}"; do
            case $cmd in
                dirb) echo -e " - DIRB: sudo apt-get install dirb";;
                curl) echo -e " - cURL: sudo apt-get install curl";;
            esac
        done
        exit 1
    fi
}

# Configurar diretório de saída
setup_output_dir() {
    if [ ! -d "${CONFIG[DEFAULT_OUTPUT_DIR]}" ]; then
        mkdir -p "${CONFIG[DEFAULT_OUTPUT_DIR]}"
        echo -e "${GREEN}[+] Diretório de saída criado: ${CONFIG[DEFAULT_OUTPUT_DIR]}${NC}"
    fi
}

# Verificar se o alvo está online
check_target() {
    local target=$1
    echo -e "${BLUE}[*] Verificando alvo: $target${NC}"
    
    if ! curl --head --silent --fail --max-time "${CONFIG[TIMEOUT]}" "$target" &> /dev/null; then
        echo -e "${YELLOW}[AVISO] Não foi possível conectar ao alvo.${NC}"
        read -p "Deseja continuar mesmo assim? (s/n): " choice
        if [[ "$choice" != "s" && "$choice" != "S" ]]; then
            exit 1
        fi
    fi
}

# Selecionar wordlist
select_wordlist() {
    echo -e "${YELLOW}Selecione a wordlist:${NC}"
    echo "1. Comum (common.txt)"
    echo "2. Grande (big.txt)"
    echo "3. Personalizada"
    read -p "Opção [1-3]: " wl_choice
    
    case $wl_choice in
        1) echo "${CONFIG[WORDLIST_COMMON]}";;
        2) echo "${CONFIG[WORDLIST_BIG]}";;
        3) 
            read -p "Caminho completo para wordlist: " custom_wl
            while [ ! -f "$custom_wl" ]; do
                echo -e "${RED}Arquivo não encontrado!${NC}"
                read -p "Tente novamente: " custom_wl
            done
            echo "$custom_wl";;
        *) 
            echo -e "${RED}Opção inválida, usando padrão${NC}"
            echo "${CONFIG[WORDLIST_COMMON]}";;
    esac
}

# Selecionar extensões
select_extensions() {
    local preset_exts=(
        ".php,.html,.js,.txt"
        ".php,.php3,.php4,.php5"
        ".asp,.aspx,.ashx"
        ".jsp,.do,.action"
        ".bak,.old,.backup"
        "Nenhuma extensão especial"
    )
    
    echo -e "${YELLOW}Selecione extensões:${NC}"
    for i in "${!preset_exts[@]}"; do
        echo "$((i+1)). ${preset_exts[i]}"
    done
    read -p "Opção [1-${#preset_exts[@]}]: " ext_choice
    
    case $ext_choice in
        [1-5]) echo "-X ${preset_exts[$((ext_choice-1))]}";;
        6) echo "";;
        *) 
            echo -e "${RED}Opção inválida, sem extensões${NC}"
            echo "";;
    esac
}

# Mostrar progresso
show_progress() {
    local pid=$1
    local spinner=('|' '/' '-' '\\')
    local i=0
    
    while kill -0 $pid 2>/dev/null; do
        i=$(( (i+1) %4 ))
        echo -ne "${BLUE}Varredura em andamento ${spinner[$i]}${NC}\r"
        sleep 0.1
    done
    echo -ne "Varredura concluída!${NC}${BLUE}${NC}\n"
}

# Gerar relatório
generate_report() {
    local output_file=$1
    local url=$2
    
    echo -e "\n${GREEN}=== RELATÓRIO FINALIZADO ===${NC}"
    echo -e "${BLUE}Alvo: ${url}${NC}"
    echo -e "${BLUE}Arquivo de saída: ${output_file}${NC}"
    
    local total_lines=$(wc -l < "$output_file")
    local found_dirs=$(grep -c "^+ " "$output_file")
    local found_files=$(grep -c "^==> DIRECTORY:" "$output_file")
    
    echo -e "\n${YELLOW}ESTATÍSTICAS:${NC}"
    echo -e " - Total de linhas: ${total_lines}"
    echo -e " - Diretórios encontrados: ${found_dirs}"
    echo -e " - Arquivos encontrados: ${found_files}"
    
    if [ $found_dirs -gt 0 ] || [ $found_files -gt 0 ]; then
        echo -e "\n${YELLOW}ITENS INTERESSANTES:${NC}"
        grep -E "^\+|^==>" "$output_file" | head -n 10
        echo -e "\n${YELLOW}Dica:${NC} Verifique o arquivo completo para mais resultados: ${output_file}"
    fi
}

# Executar varredura DIRB
run_dirb() {
    local url=$1
    local wordlist=$2
    local output="${CONFIG[DEFAULT_OUTPUT_DIR]}/$3"
    local extensions=$4
    local options=$5

    echo -e "${GREEN}[+] Iniciando varredura em: ${url}${NC}"
    echo -e "${BLUE}[*] Wordlist: ${wordlist}${NC}"
    [ -n "$extensions" ] && echo -e "${BLUE}[*] Extensões: ${extensions//-X /}${NC}"
    [ -n "$options" ] && echo -e "${BLUE}[*] Opções: ${options}${NC}"
    echo -e "${BLUE}[*] Salvando em: ${output}${NC}"
    echo

    cmd="dirb $url $wordlist -o $output $extensions $options"
    echo -e "${YELLOW}[*] Comando executado: ${cmd}${NC}"
    echo "===================================="
    
    # Executar em background para mostrar progresso
    eval $cmd &
    local pid=$!
    
    show_progress $pid
    wait $pid
    
    generate_report "$output" "$url"
}

# Menu de varreduras pré-definidas
predefined_scans() {
    local url=$1
    local scan_type=$2
    
    case $scan_type in
        1) # Básica
            run_dirb "$url" "${CONFIG[WORDLIST_COMMON]}" \
                   "dirb_basic_$(date +%Y%m%d_%H%M%S).txt" "" ""
            ;;
        2) # Com extensões
            run_dirb "$url" "${CONFIG[WORDLIST_COMMON]}" \
                   "dirb_ext_$(date +%Y%m%d_%H%M%S).txt" "-X .php,.html,.js,.txt" ""
            ;;
        3) # Agressiva
            run_dirb "$url" "${CONFIG[WORDLIST_BIG]}" \
                   "dirb_aggressive_$(date +%Y%m%d_%H%M%S).txt" "" ""
            ;;
        4) # PHP
            run_dirb "$url" "${CONFIG[WORDLIST_COMMON]}" \
                   "dirb_php_$(date +%Y%m%d_%H%M%S).txt" "-X .php,.php3,.php4,.php5,.phtml" ""
            ;;
        5) # ASP
            run_dirb "$url" "${CONFIG[WORDLIST_COMMON]}" \
                   "dirb_asp_$(date +%Y%m%d_%H%M%S).txt" "-X .asp,.aspx,.ashx,.asmx" ""
            ;;
        6) # JSP
            run_dirb "$url" "${CONFIG[WORDLIST_COMMON]}" \
                   "dirb_jsp_$(date +%Y%m%d_%H%M%S).txt" "-X .jsp,.jspx,.do,.action" ""
            ;;
        7) # Backup
            run_dirb "$url" "${CONFIG[WORDLIST_COMMON]}" \
                   "dirb_backup_$(date +%Y%m%d_%H%M%S).txt" "-X .bak,.old,.backup,.swp,.sav" ""
            ;;
    esac
}

# Menu principal
menu() {
    echo -e "${YELLOW}Selecione o tipo de varredura:${NC}"
    echo "1. Varredura Básica"
    echo "2. Varredura com Extensões Comuns"
    echo "3. Varredura Agressiva"
    echo "4. Varredura para Arquivos PHP"
    echo "5. Varredura para Arquivos ASP/ASPX"
    echo "6. Varredura para Arquivos JSP"
    echo "7. Varredura para Arquivos de Backup"
    echo "8. Varredura Personalizada"
    echo "9. Sair"
    echo

    read -p "Opção [1-9]: " choice
    
    case $choice in
        [1-7])
            read -p "Digite a URL alvo (ex: http://example.com): " url
            check_target "$url"
            predefined_scans "$url" "$choice"
            ;;
        8)
            read -p "Digite a URL alvo (ex: http://example.com): " url
            check_target "$url"
            
            wordlist=$(select_wordlist)
            extensions=$(select_extensions)
            
            echo -e "${YELLOW}Opções adicionais do DIRB:${NC}"
            echo "Exemplos:"
            echo " - -N 404 (ignorar código 404)"
            echo " - -r (não buscar recursivamente)"
            echo " - -z 100 (delay de 100ms entre requisições)"
            read -p "Digite opções adicionais: " options
            
            run_dirb "$url" "$wordlist" "dirb_custom_$(date +%Y%m%d_%H%M%S).txt" \
                   "$extensions" "$options"
            ;;
        9)
            echo -e "${GREEN}Saindo...${NC}"
            exit 0
            ;;
        *)
            echo -e "${RED}Opção inválida!${NC}"
            ;;
    esac
}

# Banner
show_banner() {
    clear
    echo -e "${RED}"
    echo "  ____  _____ ____  "
    echo " |  _ \(___ /| __ ) "
    echo " | | | | |_ \|  _ \ "
    echo " | |_| |___) | |_) |"
    echo " |____/(____/|____/ "
    echo -e "${NC}"
    echo -e "${YELLOW}=== DIRB Automation Tool ===${NC}"
    echo -e "${BLUE}Automatizando enumeração de diretórios${NC}"
    echo -e "${GREEN}Desenvolvido para pentesting web${NC}"
    echo "===================================="
    echo
}

# Inicialização
main() {
    check_dependencies
    setup_output_dir
    show_banner
    
    while true; do
        menu
        echo
        read -p "Pressione Enter para continuar ou 'q' para sair: " again
        if [[ "$again" == "q" || "$again" == "Q" ]]; then
            echo -e "${GREEN}Saindo...${NC}"
            break
        fi
    done
}

main

#!/bin/bash

# Configurações globais
declare -A CONFIG=(
    [WORDLIST_COMMON]="/usr/share/dirb/wordlists/common.txt"
    [WORDLIST_BIG]="/usr/share/dirb/wordlists/big.txt"
    [DEFAULT_OUTPUT_DIR]="$(pwd)/dirb_scans"
    [TIMEOUT]=10
    [DELAY]=1
)

# Cores para o terminal
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Banner melhorado
show_banner() {
    clear
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════╗"
    echo "║  ██████╗ ██╗██████╗ ██████╗  ██████╗    ║"
    echo "║  ██╔══██╗██║██╔══██╗██╔══██╗██╔════╝    ║"
    echo "║  ██║  ██║██║██████╔╝██████╔╝██║         ║"
    echo "║  ██║  ██║██║██╔══██╗██╔══██╗██║         ║"
    echo "║  ██████╔╝██║██║  ██║██████╔╝╚██████╗    ║"
    echo "║  ╚═════╝ ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝    ║"
    echo "╠══════════════════════════════════════════╣"
    echo "║  SCANNER DE DIRETÓRIOS - DIRB AUTOMÁTICO ║"
    echo "╚══════════════════════════════════════════╝"
    echo -e "${NC}"
    echo -e "${YELLOW}Versão: 2.0 | Autor: Seu Nome${NC}"
    echo -e "${BLUE}Data: $(date +'%d/%m/%Y %H:%M:%S')${NC}"
    echo -e "${GREEN}======================================${NC}"
    echo
}

# Verificar dependências
check_dependencies() {
    local missing=0
    local commands=("dirb" "curl")
    
    echo -e "${YELLOW}[*] Verificando dependências...${NC}"
    
    for cmd in "${commands[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            echo -e "${RED}[ERRO] Comando '$cmd' não encontrado!${NC}"
            missing=1
        else
            echo -e "${GREEN}[+] $cmd instalado${NC}"
        fi
    done
    
    if [ "$missing" -eq 1 ]; then
        echo -e "\n${YELLOW}Instale as dependências faltantes:${NC}"
        echo "sudo apt-get install dirb curl"
        exit 1
    fi
}

# Configurar diretório de saída
setup_output_dir() {
    echo -e "${YELLOW}[*] Configurando diretório de saída...${NC}"
    
    if mkdir -p "${CONFIG[DEFAULT_OUTPUT_DIR]}" 2>/dev/null; then
        echo -e "${GREEN}[+] Diretório criado: ${CONFIG[DEFAULT_OUTPUT_DIR]}${NC}"
    else
        echo -e "${RED}[ERRO] Falha ao criar diretório de saída!${NC}"
        exit 1
    fi
}

# Verificar se o alvo está online
check_target() {
    local target=$1
    
    echo -e "${YELLOW}[*] Verificando alvo: $target${NC}"
    
    if ! curl --head --silent --fail --max-time "${CONFIG[TIMEOUT]}" "$target" &> /dev/null; then
        echo -e "${RED}[ERRO] Não foi possível conectar ao alvo!${NC}"
        
        # Tentar adicionar http:// se não tiver
        if [[ ! "$target" =~ ^https?:// ]]; then
            echo -e "${YELLOW}[*] Tentando com http://...${NC}"
            target="http://$target"
            
            if ! curl --head --silent --fail --max-time "${CONFIG[TIMEOUT]}" "$target" &> /dev/null; then
                echo -e "${RED}[ERRO] Alvo ainda inacessível${NC}"
                return 1
            fi
        else
            return 1
        fi
    fi
    
    echo -e "${GREEN}[+] Alvo acessível!${NC}"
    return 0
}

# Selecionar wordlist
select_wordlist() {
    local wl_choice
    local custom_wl
    
    echo -e "\n${YELLOW}Selecione a wordlist:${NC}"
    echo "1. Comum (common.txt)"
    echo "2. Grande (big.txt)"
    echo "3. Personalizada"
    
    while true; do
        read -p "Opção [1-3]: " wl_choice
        
        case "$wl_choice" in
            1)
                if [ -f "${CONFIG[WORDLIST_COMMON]}" ]; then
                    echo "${CONFIG[WORDLIST_COMMON]}"
                    return 0
                else
                    echo -e "${RED}[ERRO] Wordlist comum não encontrada!${NC}"
                    continue
                fi
                ;;
            2)
                if [ -f "${CONFIG[WORDLIST_BIG]}" ]; then
                    echo "${CONFIG[WORDLIST_BIG]}"
                    return 0
                else
                    echo -e "${RED}[ERRO] Wordlist grande não encontrada!${NC}"
                    continue
                fi
                ;;
            3)
                read -p "Caminho completo para wordlist: " custom_wl
                if [ -f "$custom_wl" ]; then
                    echo "$custom_wl"
                    return 0
                else
                    echo -e "${RED}[ERRO] Arquivo não encontrado!${NC}"
                    continue
                fi
                ;;
            *)
                echo -e "${RED}Opção inválida! Tente novamente.${NC}"
                ;;
        esac
    done
}

# Selecionar extensões
select_extensions() {
    local ext_choice
    
    echo -e "\n${YELLOW}Selecione extensões:${NC}"
    echo "1. .php,.html,.js,.txt"
    echo "2. .php,.php3,.php4,.php5"
    echo "3. .asp,.aspx,.ashx"
    echo "4. .jsp,.do,.action"
    echo "5. .bak,.old,.backup"
    echo "6. Nenhuma extensão especial"
    
    while true; do
        read -p "Opção [1-6]: " ext_choice
        
        case "$ext_choice" in
            1) echo "-X .php,.html,.js,.txt"; return 0 ;;
            2) echo "-X .php,.php3,.php4,.php5"; return 0 ;;
            3) echo "-X .asp,.aspx,.ashx"; return 0 ;;
            4) echo "-X .jsp,.do,.action"; return 0 ;;
            5) echo "-X .bak,.old,.backup"; return 0 ;;
            6) echo ""; return 0 ;;
            *) echo -e "${RED}Opção inválida! Tente novamente.${NC}" ;;
        esac
    done
}

# Mostrar progresso
show_progress() {
    local pid=$1
    local spinner=('⣾' '⣽' '⣻' '⢿' '⡿' '⣟' '⣯' '⣷')
    local i=0
    
    while ps -p "$pid" > /dev/null 2>&1; do
        i=$(( (i+1) %8 ))
        echo -ne "${BLUE}Varredura em andamento ${spinner[$i]}${NC}\r"
        sleep 0.1
    done
    
    echo -ne "${GREEN}✓ Varredura concluída!${NC}${BLUE}${NC}\n"
}

# Gerar relatório
generate_report() {
    local output_file=$1
    local url=$2
    
    echo -e "\n${GREEN}╔══════════════════════════════════════════╗"
    echo -e "║             RELATÓRIO FINALIZADO           ║"
    echo -e "╚══════════════════════════════════════════╝${NC}"
    
    echo -e "\n${CYAN}Alvo:${NC} $url"
    echo -e "${CYAN}Arquivo de saída:${NC} $output_file"
    
    if [ ! -f "$output_file" ]; then
        echo -e "${RED}[ERRO] Arquivo de resultados não encontrado!${NC}"
        return 1
    fi
    
    local total_lines=$(wc -l < "$output_file" 2>/dev/null)
    local found_dirs=$(grep -c -E '^\+ [0-9]{3}' "$output_file" 2>/dev/null)
    local found_files=$(grep -c '^==> DIRECTORY:' "$output_file" 2>/dev/null)
    
    echo -e "\n${YELLOW}╔══════════════════════════════════════════╗"
    echo -e "║               ESTATÍSTICAS              ║"
    echo -e "╚══════════════════════════════════════════╝${NC}"
    echo -e "${MAGENTA}Total de linhas:${NC} ${total_lines:-0}"
    echo -e "${MAGENTA}Diretórios encontrados:${NC} ${found_dirs:-0}"
    echo -e "${MAGENTA}Arquivos encontrados:${NC} ${found_files:-0}"
    
    if [ "$found_dirs" -gt 0 ] || [ "$found_files" -gt 0 ]; then
        echo -e "\n${YELLOW}╔══════════════════════════════════════════╗"
        echo -e "║           ITENS INTERESSANTES           ║"
        echo -e "╚══════════════════════════════════════════╝${NC}"
        grep -E '^\+ [0-9]{3}|^==> DIRECTORY:' "$output_file" | head -n 10 | while read -r line; do
            echo -e "${CYAN}$line${NC}"
        done
        
        echo -e "\n${GREEN}Dica:${NC} Verifique o arquivo completo para mais resultados:"
        echo -e "${BLUE}$output_file${NC}"
    else
        echo -e "\n${RED}Nenhum resultado relevante encontrado.${NC}"
    fi
}

# Executar varredura DIRB
run_dirb() {
    local url=$1
    local wordlist=$2
    local output_file="${CONFIG[DEFAULT_OUTPUT_DIR]}/$3"
    local extensions=$4
    local options=$5

    # Sanitizar opções
    options=$(echo "$options" | tr -d ';&|<>()$`')

    echo -e "\n${GREEN}╔══════════════════════════════════════════╗"
    echo -e "║          INICIANDO VARREDURA DIRB        ║"
    echo -e "╚══════════════════════════════════════════╝${NC}"
    
    echo -e "${CYAN}Alvo:${NC} $url"
    echo -e "${CYAN}Wordlist:${NC} $wordlist"
    [ -n "$extensions" ] && echo -e "${CYAN}Extensões:${NC} ${extensions//-X /}"
    [ -n "$options" ] && echo -e "${CYAN}Opções:${NC} $options"
    echo -e "${CYAN}Saída:${NC} $output_file"
    
    local cmd="dirb '$url' '$wordlist' -o '$output_file' $extensions $options"
    echo -e "\n${YELLOW}[*] Comando executado:${NC}"
    echo -e "${BLUE}$cmd${NC}"
    
    echo -e "\n${MAGENTA}Iniciando varredura...${NC}"
    
    # Executar em background
    eval "$cmd" > /dev/null 2>&1 &
    local pid=$!
    
    show_progress "$pid"
    wait "$pid"
    
    generate_report "$output_file" "$url"
}

# Varreduras pré-definidas
predefined_scans() {
    local url=$1
    local scan_type=$2
    
    case "$scan_type" in
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
    while true; do
        echo -e "\n${YELLOW}╔══════════════════════════════════════════╗"
        echo -e "║          MENU PRINCIPAL - DIRB SCANNER      ║"
        echo -e "╚══════════════════════════════════════════╝${NC}"
        echo -e "${CYAN}1. Varredura Básica${NC}"
        echo -e "${CYAN}2. Varredura com Extensões Comuns${NC}"
        echo -e "${CYAN}3. Varredura Agressiva${NC}"
        echo -e "${CYAN}4. Varredura para Arquivos PHP${NC}"
        echo -e "${CYAN}5. Varredura para Arquivos ASP/ASPX${NC}"
        echo -e "${CYAN}6. Varredura para Arquivos JSP${NC}"
        echo -e "${CYAN}7. Varredura para Arquivos de Backup${NC}"
        echo -e "${CYAN}8. Varredura Personalizada${NC}"
        echo -e "${RED}9. Sair${NC}"
        
        read -p "Opção [1-9]: " choice
        
        case "$choice" in
            1|2|3|4|5|6|7)
                read -p "Digite a URL alvo (ex: http://example.com): " url
                if check_target "$url"; then
                    predefined_scans "$url" "$choice"
                fi
                ;;
            8)
                read -p "Digite a URL alvo (ex: http://example.com): " url
                if check_target "$url"; then
                    wordlist=$(select_wordlist)
                    extensions=$(select_extensions)
                    
                    echo -e "\n${YELLOW}Opções adicionais do DIRB:${NC}"
                    echo -e "${BLUE}Exemplos:${NC}"
                    echo -e " - ${CYAN}-N 404${NC} (ignorar código 404)"
                    echo -e " - ${CYAN}-r${NC} (não buscar recursivamente)"
                    echo -e " - ${CYAN}-z 100${NC} (delay de 100ms entre requisições)"
                    echo -e " - ${CYAN}-p http://proxy:8080${NC} (usar proxy)"
                    read -p "Digite opções adicionais: " options
                    
                    run_dirb "$url" "$wordlist" "dirb_custom_$(date +%Y%m%d_%H%M%S).txt" \
                           "$extensions" "$options"
                fi
                ;;
            9)
                echo -e "\n${GREEN}Encerrando o DIRB Scanner...${NC}"
                exit 0
                ;;
            *)
                echo -e "${RED}Opção inválida! Tente novamente.${NC}"
                ;;
        esac
        
        read -p "Pressione Enter para continuar..."
        show_banner
    done
}

# Função principal
main() {
    show_banner
    check_dependencies
    setup_output_dir
    menu
}

# Iniciar o script
main

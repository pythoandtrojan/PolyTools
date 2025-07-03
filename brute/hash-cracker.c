#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/md4.h> // Para NTLM
#include <pthread.h>
#include <sys/stat.h>
#include <unistd.h>
#include <ctype.h>

// Constantes e configurações
#define MAX_WORD_LENGTH 1024
#define MAX_HASH_LENGTH 128
#define PROGRESS_BAR_WIDTH 50
#define NUM_THREADS 8  // Aumentado para melhor desempenho

// Tipos de hash suportados
typedef enum {
    HASH_MD5,
    HASH_SHA1,
    HASH_SHA256,
    HASH_SHA512,
    HASH_NTLM,
    HASH_UNKNOWN
} HashType;

// Estrutura para thread
typedef struct {
    FILE *wordlist;
    const char *target_hash;
    HashType hash_type;
    int *found;
    char *result;
    pthread_mutex_t *mutex;
    long start_pos;
    long end_pos;
    unsigned long *words_processed;
    unsigned long total_words;
} ThreadData;

// Cores para o terminal
#define RED     "\x1B[31m"
#define GREEN   "\x1B[32m"
#define YELLOW  "\x1B[33m"
#define BLUE    "\x1B[34m"
#define MAGENTA "\x1B[35m"
#define CYAN    "\x1B[36m"
#define RESET   "\x1B[0m"
#define BOLD    "\x1B[1m"

// Protótipos de funções
void clear_screen();
void show_banner();
void dictionary_attack();
void brute_force_attack();
void hash_checker();
void wordlist_generator();
void calculate_hash(const char *input, HashType type, unsigned char *output, size_t length);
void print_progress_bar(float progress, double speed);
HashType get_hash_type(const char *type_str);
void *thread_function(void *arg);
unsigned long count_lines(FILE *file);
void print_hash_info(HashType type);
void convert_hash_to_string(const unsigned char *digest, HashType type, char *output);
int is_valid_hash(const char *hash, HashType type);
void save_result(const char *filename, const char *hash, const char *password, double time_spent, const char *hash_type);

// Função principal
int main() {
    int choice;
    
    do {
        clear_screen();
        show_banner();
        
        printf(BOLD "MENU PRINCIPAL:\n" RESET);
        printf(CYAN "1. Ataque por Dicionário (Otimizado)\n");
        printf("2. Ataque por Força Bruta\n");
        printf("3. Verificador de Hash\n");
        printf("4. Gerador de Wordlist\n");
        printf("5. Sair\n\n" RESET);
        
        printf("Selecione uma opção: ");
        if (scanf("%d", &choice) != 1) {
            while (getchar() != '\n');
            choice = 0;
        }
        
        switch(choice) {
            case 1:
                dictionary_attack();
                break;
            case 2:
                brute_force_attack();
                break;
            case 3:
                hash_checker();
                break;
            case 4:
                wordlist_generator();
                break;
            case 5:
                printf("\nSaindo...\n");
                break;
            default:
                printf(RED "\nOpção inválida!\n" RESET);
        }
        
        if (choice != 5) {
            printf("\nPressione Enter para continuar...");
            while (getchar() != '\n');
            getchar();
        }
        
    } while (choice != 5);
    
    return 0;
}

// Implementação das funções

void clear_screen() {
    system("clear || cls");
}

void show_banner() {
    printf(BOLD BLUE "\n");
    printf("   _   _           _       _____ _          _ _           \n");
    printf("  | | | |         | |     |_   _| |        | | |          \n");
    printf("  | |_| | __ _ ___| |__     | | | |__   ___| | | ___ _ __ \n");
    printf("  |  _  |/ _` / __| '_ \\    | | | '_ \\ / _ \\ | |/ _ \\ '__|\n");
    printf("  | | | | (_| \\__ \\ | | |  _| |_| | | |  __/ | |  __/ |   \n");
    printf("  \\_| |_/\\__,_|___/_| |_|  \\___/_| |_|\\___|_|_|\\___|_|   \n\n" RESET);
    printf(YELLOW "  [Hash Cracker Avançado - Versão 3.0 - Corrigida e Otimizada]\n\n" RESET);
}

HashType get_hash_type(const char *type_str) {
    if (strcasecmp(type_str, "md5") == 0) return HASH_MD5;
    if (strcasecmp(type_str, "sha1") == 0) return HASH_SHA1;
    if (strcasecmp(type_str, "sha256") == 0) return HASH_SHA256;
    if (strcasecmp(type_str, "sha512") == 0) return HASH_SHA512;
    if (strcasecmp(type_str, "ntlm") == 0) return HASH_NTLM;
    return HASH_UNKNOWN;
}

void print_hash_info(HashType type) {
    const char *name = "";
    int length = 0;
    
    switch(type) {
        case HASH_MD5:    name = "MD5";    length = 32; break;
        case HASH_SHA1:   name = "SHA-1";  length = 40; break;
        case HASH_SHA256: name = "SHA-256";length = 64; break;
        case HASH_SHA512: name = "SHA-512";length = 128; break;
        case HASH_NTLM:   name = "NTLM";   length = 32; break;
        default: return;
    }
    
    printf(MAGENTA "\n[*] Informações do Hash:\n" RESET);
    printf("Tipo: %s\n", name);
    printf("Comprimento esperado: %d caracteres\n", length);
    printf("Exemplo: ");
    
    unsigned char digest[MAX_HASH_LENGTH];
    char hash_str[MAX_HASH_LENGTH*2 + 1];
    calculate_hash("exemplo", type, digest, strlen("exemplo"));
    convert_hash_to_string(digest, type, hash_str);
    printf("%s\n", hash_str);
}

void calculate_hash(const char *input, HashType type, unsigned char *output, size_t length) {
    switch(type) {
        case HASH_MD5:
            MD5((unsigned char*)input, length, output);
            break;
        case HASH_SHA1:
            SHA1((unsigned char*)input, length, output);
            break;
        case HASH_SHA256:
            SHA256((unsigned char*)input, length, output);
            break;
        case HASH_SHA512:
            SHA512((unsigned char*)input, length, output);
            break;
        case HASH_NTLM:
            MD4((unsigned char*)input, length, output);
            break;
        default:
            memset(output, 0, MAX_HASH_LENGTH);
    }
}

void convert_hash_to_string(const unsigned char *digest, HashType type, char *output) {
    int hash_len = 16; // Padrão para MD5, SHA1 (20 mas mostramos 16), NTLM
    
    switch(type) {
        case HASH_SHA256: hash_len = 32; break;
        case HASH_SHA512: hash_len = 64; break;
        case HASH_SHA1:   hash_len = 20; break;
        case HASH_NTLM:   hash_len = 16; break;
        default:          hash_len = 16; // MD5
    }
    
    for (int i = 0; i < hash_len; i++) {
        sprintf(&output[i*2], "%02x", (unsigned int)digest[i]);
    }
    output[hash_len*2] = '\0';
}

int is_valid_hash(const char *hash, HashType type) {
    int expected_length = 0;
    
    switch(type) {
        case HASH_MD5:    expected_length = 32; break;
        case HASH_SHA1:   expected_length = 40; break;
        case HASH_SHA256: expected_length = 64; break;
        case HASH_SHA512: expected_length = 128; break;
        case HASH_NTLM:   expected_length = 32; break;
        default: return 0;
    }
    
    // Verificar comprimento
    if (strlen(hash) != expected_length) return 0;
    
    // Verificar se é hexadecimal
    for (int i = 0; i < expected_length; i++) {
        if (!isxdigit(hash[i])) return 0;
    }
    
    return 1;
}

void print_progress_bar(float progress, double speed) {
    int pos = PROGRESS_BAR_WIDTH * progress;
    printf(BOLD BLUE "[");
    for (int i = 0; i < PROGRESS_BAR_WIDTH; ++i) {
        if (i < pos) printf("=");
        else if (i == pos) printf(">");
        else printf(" ");
    }
    printf("] %d%% (%.2f hashes/seg)\r" RESET, (int)(progress * 100.0), speed);
    fflush(stdout);
}

unsigned long count_lines(FILE *file) {
    unsigned long count = 0;
    char ch;
    
    rewind(file);
    while(!feof(file)) {
        ch = fgetc(file);
        if(ch == '\n') count++;
    }
    rewind(file);
    
    return count;
}

void *thread_function(void *arg) {
    ThreadData *data = (ThreadData *)arg;
    char word[MAX_WORD_LENGTH];
    unsigned char digest[MAX_HASH_LENGTH];
    char hash_str[MAX_HASH_LENGTH*2 + 1];
    unsigned long local_words = 0;
    
    fseek(data->wordlist, data->start_pos, SEEK_SET);
    
    while (ftell(data->wordlist) < data->end_pos && !(*data->found)) {
        if (fgets(word, sizeof(word), data->wordlist) == NULL) break;
        
        // Remover nova linha
        word[strcspn(word, "\n\r")] = 0;
        
        // Calcular hash
        calculate_hash(word, data->hash_type, digest, strlen(word));
        convert_hash_to_string(digest, data->hash_type, hash_str);
        
        // Verificar se encontramos a senha
        if (strcasecmp(hash_str, data->target_hash) == 0) {
            pthread_mutex_lock(data->mutex);
            *data->found = 1;
            strncpy(data->result, word, MAX_WORD_LENGTH);
            pthread_mutex_unlock(data->mutex);
            break;
        }
        
        local_words++;
        
        // Atualizar contador de palavras processadas periodicamente
        if (local_words % 100 == 0) {
            pthread_mutex_lock(data->mutex);
            *data->words_processed += 100;
            pthread_mutex_unlock(data->mutex);
        }
    }
    
    // Atualizar contador final
    pthread_mutex_lock(data->mutex);
    *data->words_processed += local_words % 100;
    pthread_mutex_unlock(data->mutex);
    
    return NULL;
}

void dictionary_attack() {
    clear_screen();
    show_banner();
    
    char wordlist_path[MAX_WORD_LENGTH];
    char hash_to_crack[MAX_HASH_LENGTH*2 + 1];
    char hash_type_str[10];
    char output_file[MAX_WORD_LENGTH] = {0};
    
    printf(BOLD "[+] ATAQUE POR DICIONÁRIO OTIMIZADO\n\n" RESET);
    
    // Obter entradas do usuário
    printf("Caminho para wordlist: ");
    if (scanf("%1023s", wordlist_path) != 1) {
        printf(RED "\n[!] Entrada inválida!\n" RESET);
        return;
    }
    
    printf("Hash para quebrar: ");
    if (scanf("%127s", hash_to_crack) != 1) {
        printf(RED "\n[!] Entrada inválida!\n" RESET);
        return;
    }
    
    printf("Tipo de hash (md5/sha1/sha256/sha512/ntlm): ");
    if (scanf("%9s", hash_type_str) != 1) {
        printf(RED "\n[!] Entrada inválida!\n" RESET);
        return;
    }
    
    // Limpar buffer
    while (getchar() != '\n');
    
    printf("Salvar resultados em (deixe em branco para não salvar): ");
    fgets(output_file, sizeof(output_file), stdin);
    output_file[strcspn(output_file, "\n")] = 0;
    
    HashType hash_type = get_hash_type(hash_type_str);
    if (hash_type == HASH_UNKNOWN) {
        printf(RED "\n[!] Tipo de hash não suportado!\n" RESET);
        return;
    }
    
    // Validar o hash fornecido
    if (!is_valid_hash(hash_to_crack, hash_type)) {
        printf(RED "\n[!] Hash inválido para o tipo %s!\n" RESET, hash_type_str);
        print_hash_info(hash_type);
        return;
    }
    
    FILE *wordlist = fopen(wordlist_path, "r");
    if (!wordlist) {
        printf(RED "\n[!] Erro ao abrir wordlist: %s\n" RESET, wordlist_path);
        return;
    }
    
    // Contar linhas para progresso
    unsigned long total_words = count_lines(wordlist);
    if (total_words == 0) {
        printf(RED "\n[!] Wordlist vazia!\n" RESET);
        fclose(wordlist);
        return;
    }
    
    // Calcular tamanho do arquivo para divisão entre threads
    fseek(wordlist, 0, SEEK_END);
    long file_size = ftell(wordlist);
    rewind(wordlist);
    
    printf("\n" YELLOW "[*] Iniciando ataque com %d threads...\n" RESET, NUM_THREADS);
    printf("[*] Tamanho da wordlist: %ld bytes\n", file_size);
    printf("[*] Número de palavras: %lu\n", total_words);
    printf("[*] Pressione Ctrl+C para parar\n\n");
    
    // Configuração das threads
    pthread_t threads[NUM_THREADS];
    ThreadData thread_data[NUM_THREADS];
    pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
    int found = 0;
    char result[MAX_WORD_LENGTH] = {0};
    unsigned long words_processed = 0;
    clock_t start = clock();
    
    // Dividir trabalho entre threads
    for (int i = 0; i < NUM_THREADS; i++) {
        thread_data[i].wordlist = wordlist;
        thread_data[i].target_hash = hash_to_crack;
        thread_data[i].hash_type = hash_type;
        thread_data[i].found = &found;
        thread_data[i].result = result;
        thread_data[i].mutex = &mutex;
        thread_data[i].start_pos = i * (file_size / NUM_THREADS);
        thread_data[i].end_pos = (i + 1) * (file_size / NUM_THREADS);
        thread_data[i].words_processed = &words_processed;
        thread_data[i].total_words = total_words;
        
        // Ajustar posição de início para começar no início de uma linha
        if (i > 0) {
            fseek(wordlist, thread_data[i].start_pos, SEEK_SET);
            while (fgetc(wordlist) != '\n' && ftell(wordlist) < file_size);
            thread_data[i].start_pos = ftell(wordlist);
        }
        
        pthread_create(&threads[i], NULL, thread_function, &thread_data[i]);
    }
    
    // Exibir progresso
    while (!found && words_processed < total_words) {
        float progress = (float)words_processed / total_words;
        double elapsed = (double)(clock() - start) / CLOCKS_PER_SEC;
        double speed = elapsed > 0 ? words_processed / elapsed : 0;
        
        print_progress_bar(progress, speed);
        
        // Verificar a cada 100ms
        usleep(100000);
    }
    
    // Aguardar conclusão das threads
    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }
    
    pthread_mutex_destroy(&mutex);
    
    clock_t end = clock();
    double time_spent = (double)(end - start) / CLOCKS_PER_SEC;
    
    // Exibir resultados
    if (found) {
        printf(GREEN "\n\n[+] SENHA ENCONTRADA: %s\n" RESET, result);
        
        if (strlen(output_file) > 0) {
            save_result(output_file, hash_to_crack, result, time_spent, hash_type_str);
            printf(GREEN "[+] Resultados salvos em: %s\n" RESET, output_file);
        }
    } else {
        printf(RED "\n\n[-] Senha não encontrada na wordlist!\n" RESET);
    }
    
    printf("[+] Palavras testadas: %lu de %lu (%.2f%%)\n", 
           words_processed, total_words, 
           (float)words_processed / total_words * 100);
    printf("[+] Tempo decorrido: %.2f segundos\n", time_spent);
    printf("[+] Velocidade média: %.2f hashes/segundo\n", 
           words_processed / (time_spent > 0 ? time_spent : 1));
    
    fclose(wordlist);
}

void save_result(const char *filename, const char *hash, const char *password, 
                double time_spent, const char *hash_type) {
    FILE *out = fopen(filename, "a");
    if (!out) {
        printf(RED "[!] Erro ao salvar resultados no arquivo!\n" RESET);
        return;
    }
    
    fprintf(out, "=== Resultado da Quebra de Hash ===\n");
    fprintf(out, "Tipo de Hash: %s\n", hash_type);
    fprintf(out, "Hash: %s\n", hash);
    fprintf(out, "Senha encontrada: %s\n", password);
    fprintf(out, "Tempo decorrido: %.2f segundos\n", time_spent);
    fprintf(out, "Data: %s\n", ctime(&(time_t){time(NULL)}));
    fprintf(out, "==================================\n\n");
    
    fclose(out);
}

void brute_force_attack() {
    clear_screen();
    show_banner();
    printf(BOLD "[+] ATAQUE POR FORÇA BRUTA\n\n" RESET);
    
    char charset[256];
    int min_len, max_len;
    char hash_to_crack[MAX_HASH_LENGTH*2 + 1];
    char hash_type_str[10];
    char output_file[MAX_WORD_LENGTH] = {0};
    
    printf("Defina os caracteres a serem usados (ex: abc123): ");
    if (scanf("%255s", charset) != 1) {
        printf(RED "\n[!] Entrada inválida!\n" RESET);
        return;
    }
    
    printf("Comprimento mínimo da senha: ");
    if (scanf("%d", &min_len) != 1) {
        printf(RED "\n[!] Entrada inválida!\n" RESET);
        return;
    }
    
    printf("Comprimento máximo da senha: ");
    if (scanf("%d", &max_len) != 1) {
        printf(RED "\n[!] Entrada inválida!\n" RESET);
        return;
    }
    
    printf("Hash para quebrar: ");
    if (scanf("%127s", hash_to_crack) != 1) {
        printf(RED "\n[!] Entrada inválida!\n" RESET);
        return;
    }
    
    printf("Tipo de hash (md5/sha1/sha256/sha512/ntlm): ");
    if (scanf("%9s", hash_type_str) != 1) {
        printf(RED "\n[!] Entrada inválida!\n" RESET);
        return;
    }
    
    // Limpar buffer
    while (getchar() != '\n');
    
    printf("Salvar resultados em (deixe em branco para não salvar): ");
    fgets(output_file, sizeof(output_file), stdin);
    output_file[strcspn(output_file, "\n")] = 0;
    
    HashType hash_type = get_hash_type(hash_type_str);
    if (hash_type == HASH_UNKNOWN) {
        printf(RED "\n[!] Tipo de hash não suportado!\n" RESET);
        return;
    }
    
    // Validar o hash fornecido
    if (!is_valid_hash(hash_to_crack, hash_type)) {
        printf(RED "\n[!] Hash inválido para o tipo %s!\n" RESET, hash_type_str);
        print_hash_info(hash_type);
        return;
    }
    
    printf("\n" YELLOW "[*] Iniciando ataque por força bruta...\n" RESET);
    printf("[*] Intervalo de comprimento: %d a %d caracteres\n", min_len, max_len);
    printf("[*] Conjunto de caracteres: %s\n", charset);
    printf("[*] Pressione Ctrl+C para parar\n\n");
    
    // Implementação simplificada (versão completa teria geração de combinações)
    printf("Esta funcionalidade está em desenvolvimento.\n");
    printf("Implementação completa incluirá geração sistemática de todas as combinações possíveis.\n");
}

void hash_checker() {
    clear_screen();
    show_banner();
    printf(BOLD "[+] VERIFICADOR DE HASH\n\n" RESET);
    
    char input[MAX_WORD_LENGTH];
    char hash_type_str[10];
    
    printf("Digite o texto para hash: ");
    if (fgets(input, sizeof(input), stdin) == NULL) {
        printf(RED "\n[!] Erro ao ler entrada!\n" RESET);
        return;
    }
    input[strcspn(input, "\n")] = 0;
    
    printf("Tipo de hash (md5/sha1/sha256/sha512/ntlm): ");
    if (scanf("%9s", hash_type_str) != 1) {
        printf(RED "\n[!] Entrada inválida!\n" RESET);
        return;
    }
    
    HashType hash_type = get_hash_type(hash_type_str);
    if (hash_type == HASH_UNKNOWN) {
        printf(RED "\n[!] Tipo de hash não suportado!\n" RESET);
        return;
    }
    
    unsigned char digest[MAX_HASH_LENGTH];
    char hash_str[MAX_HASH_LENGTH*2 + 1];
    
    calculate_hash(input, hash_type, digest, strlen(input));
    convert_hash_to_string(digest, hash_type, hash_str);
    
    printf("\n" GREEN "[+] Hash %s do texto \"%s\":\n%s\n" RESET, 
           hash_type_str, input, hash_str);
    
    print_hash_info(hash_type);
}

void wordlist_generator() {
    clear_screen();
    show_banner();
    printf(BOLD "[+] GERADOR DE WORDLIST\n\n" RESET);
    
    char output_file[MAX_WORD_LENGTH];
    char base_words[5][MAX_WORD_LENGTH];
    int num_words = 0;
    
    printf("Digite o nome do arquivo de saída: ");
    if (scanf("%1023s", output_file) != 1) {
        printf(RED "\n[!] Entrada inválida!\n" RESET);
        return;
    }
    
    // Limpar buffer
    while (getchar() != '\n');
    
    printf("Digite até 5 palavras base (uma por linha, deixe em branco para terminar):\n");
    for (num_words = 0; num_words < 5; num_words++) {
        printf("Palavra %d: ", num_words + 1);
        if (fgets(base_words[num_words], sizeof(base_words[num_words]), stdin) == NULL) break;
        
        base_words[num_words][strcspn(base_words[num_words], "\n")] = 0;
        
        if (strlen(base_words[num_words]) == 0) break;
    }
    
    if (num_words == 0) {
        printf(RED "\n[!] Nenhuma palavra fornecida!\n" RESET);
        return;
    }
    
    printf("\n" YELLOW "[*] Gerando wordlist básica...\n" RESET);
    
    FILE *out = fopen(output_file, "w");
    if (!out) {
        printf(RED "\n[!] Erro ao criar arquivo de saída!\n" RESET);
        return;
    }
    
    // Gerar combinações simples
    for (int i = 0; i < num_words; i++) {
        fprintf(out, "%s\n", base_words[i]);
        
        // Adicionar variações com números
        for (int j = 0; j < 100; j++) {
            fprintf(out, "%s%d\n", base_words[i], j);
            fprintf(out, "%s%d%d\n", base_words[i], j, j);
        }
        
        // Adicionar variações com letras maiúsculas
        char upper[MAX_WORD_LENGTH];
        strcpy(upper, base_words[i]);
        if (strlen(upper) > 0) upper[0] = toupper(upper[0]);
        fprintf(out, "%s\n", upper);
    }
    
    // Adicionar combinações de palavras
    if (num_words > 1) {
        for (int i = 0; i < num_words; i++) {
            for (int j = 0; j < num_words; j++) {
                if (i != j) {
                    fprintf(out, "%s%s\n", base_words[i], base_words[j]);
                    fprintf(out, "%s_%s\n", base_words[i], base_words[j]);
                    fprintf(out, "%s.%s\n", base_words[i], base_words[j]);
                }
            }
        }
    }
    
    fclose(out);
    
    printf(GREEN "\n[+] Wordlist gerada com sucesso em: %s\n" RESET, output_file);
    
    // Mostrar estatísticas
    FILE *check = fopen(output_file, "r");
    if (check) {
        unsigned long line_count = count_lines(check);
        fclose(check);
        printf("[+] Número de palavras geradas: %lu\n", line_count);
    }
}

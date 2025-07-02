#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <pthread.h>
#include <zlib.h>
#include <sys/stat.h>

// Constantes e configurações
#define MAX_WORD_LENGTH 1024
#define MAX_HASH_LENGTH 128
#define PROGRESS_BAR_WIDTH 50
#define NUM_THREADS 4

// Tipos de hash suportados
typedef enum {
    HASH_MD5,
    HASH_SHA1,
    HASH_SHA256,
    HASH_SHA512,
    HASH_NTLM
} HashType;

// Estrutura para thread
typedef struct {
    FILE *wordlist;
    char *target_hash;
    HashType hash_type;
    int *found;
    char *result;
    pthread_mutex_t *mutex;
    long start_pos;
    long end_pos;
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
void calculate_hash(const char *input, HashType type, unsigned char *output);
void print_progress_bar(float progress);
HashType get_hash_type(const char *type_str);
void *thread_function(void *arg);

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
    system("clear");
}

void show_banner() {
    printf(BOLD BLUE "\n");
    printf("   _   _           _       _____ _          _ _           \n");
    printf("  | | | |         | |     |_   _| |        | | |          \n");
    printf("  | |_| | __ _ ___| |__     | | | |__   ___| | | ___ _ __ \n");
    printf("  |  _  |/ _` / __| '_ \\    | | | '_ \\ / _ \\ | |/ _ \\ '__|\n");
    printf("  | | | | (_| \\__ \\ | | |  _| |_| | | |  __/ | |  __/ |   \n");
    printf("  \\_| |_/\\__,_|___/_| |_|  \\___/_| |_|\\___|_|_|\\___|_|   \n\n" RESET);
    printf(YELLOW "  [Hash Cracker Avançado para Termux - Versão 2.0]\n\n" RESET);
}

HashType get_hash_type(const char *type_str) {
    if (strcasecmp(type_str, "md5") == 0) return HASH_MD5;
    if (strcasecmp(type_str, "sha1") == 0) return HASH_SHA1;
    if (strcasecmp(type_str, "sha256") == 0) return HASH_SHA256;
    if (strcasecmp(type_str, "sha512") == 0) return HASH_SHA512;
    if (strcasecmp(type_str, "ntlm") == 0) return HASH_NTLM;
    return -1;
}

void calculate_hash(const char *input, HashType type, unsigned char *output) {
    switch(type) {
        case HASH_MD5:
            MD5((unsigned char*)input, strlen(input), output);
            break;
        case HASH_SHA1:
            SHA1((unsigned char*)input, strlen(input), output);
            break;
        case HASH_SHA256:
            SHA256((unsigned char*)input, strlen(input), output);
            break;
        case HASH_SHA512:
            SHA512((unsigned char*)input, strlen(input), output);
            break;
        case HASH_NTLM:
            // Implementação simplificada do NTLM
            MD4((unsigned char*)input, strlen(input), output);
            break;
        default:
            memset(output, 0, 64);
    }
}

void print_progress_bar(float progress) {
    int pos = PROGRESS_BAR_WIDTH * progress;
    printf(BOLD BLUE "[");
    for (int i = 0; i < PROGRESS_BAR_WIDTH; ++i) {
        if (i < pos) printf("=");
        else if (i == pos) printf(">");
        else printf(" ");
    }
    printf("] %d%%\r" RESET, (int)(progress * 100.0));
    fflush(stdout);
}

void *thread_function(void *arg) {
    ThreadData *data = (ThreadData *)arg;
    char word[MAX_WORD_LENGTH];
    unsigned char digest[MAX_HASH_LENGTH];
    char hash[MAX_HASH_LENGTH*2 + 1];
    
    fseek(data->wordlist, data->start_pos, SEEK_SET);
    
    while (ftell(data->wordlist) < data->end_pos && !(*data->found)) {
        if (fgets(word, sizeof(word), data->wordlist) == NULL) break;
        
        word[strcspn(word, "\n")] = 0;
        
        calculate_hash(word, data->hash_type, digest);
        
        // Converter hash para string hexadecimal
        for (int i = 0; i < (data->hash_type == HASH_SHA512 ? 64 : 32); i++)
            sprintf(&hash[i*2], "%02x", (unsigned int)digest[i]);
        
        if (strcasecmp(hash, data->target_hash) == 0) {
            pthread_mutex_lock(data->mutex);
            *data->found = 1;
            strncpy(data->result, word, MAX_WORD_LENGTH);
            pthread_mutex_unlock(data->mutex);
            break;
        }
    }
    
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
    scanf("%1023s", wordlist_path);
    
    printf("Hash para quebrar: ");
    scanf("%127s", hash_to_crack);
    
    printf("Tipo de hash (md5/sha1/sha256/sha512/ntlm): ");
    scanf("%9s", hash_type_str);
    
    printf("Salvar resultados em (deixe em branco para não salvar): ");
    scanf(" %1023[^\n]", output_file);
    
    HashType hash_type = get_hash_type(hash_type_str);
    if (hash_type == -1) {
        printf(RED "\n[!] Tipo de hash não suportado!\n" RESET);
        return;
    }
    
    FILE *wordlist = fopen(wordlist_path, "r");
    if (!wordlist) {
        printf(RED "\n[!] Erro ao abrir wordlist!\n" RESET);
        return;
    }
    
    // Calcular tamanho do arquivo para divisão entre threads
    fseek(wordlist, 0, SEEK_END);
    long file_size = ftell(wordlist);
    rewind(wordlist);
    
    printf("\n" YELLOW "[*] Iniciando ataque com %d threads...\n" RESET, NUM_THREADS);
    printf("[*] Tamanho da wordlist: %ld bytes\n", file_size);
    printf("[*] Pressione Ctrl+C para parar\n\n");
    
    // Configuração das threads
    pthread_t threads[NUM_THREADS];
    ThreadData thread_data[NUM_THREADS];
    pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
    int found = 0;
    char result[MAX_WORD_LENGTH] = {0};
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
        
        pthread_create(&threads[i], NULL, thread_function, &thread_data[i]);
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
        printf(GREEN "\n[+] SENHA ENCONTRADA: %s\n" RESET, result);
        
        if (strlen(output_file) > 0) {
            FILE *out = fopen(output_file, "a");
            if (out) {
                fprintf(out, "Hash: %s\nSenha: %s\nTempo: %.2f segundos\n\n", 
                       hash_to_crack, result, time_spent);
                fclose(out);
                printf(GREEN "[+] Resultados salvos em: %s\n" RESET, output_file);
            }
        }
    } else {
        printf(RED "\n[-] Senha não encontrada na wordlist!\n" RESET);
    }
    
    printf("[+] Tempo decorrido: %.2f segundos\n", time_spent);
    fclose(wordlist);
}

// Implementações simplificadas das outras funções
void brute_force_attack() {
    clear_screen();
    show_banner();
    printf(BOLD "[+] ATAQUE POR FORÇA BRUTA\n\n" RESET);
    printf("Esta funcionalidade está em desenvolvimento.\n");
    printf("Implementação completa incluirá:\n");
    printf("- Configuração de máscaras de caracteres\n");
    printf("- Intervalos personalizados\n");
    printf("- Otimização com OpenMP\n");
}

void hash_checker() {
    clear_screen();
    show_banner();
    printf(BOLD "[+] VERIFICADOR DE HASH\n\n" RESET);
    
    char input[256];
    char hash_type_str[10];
    
    printf("Digite o texto para hash: ");
    scanf(" %255[^\n]", input);
    
    printf("Tipo de hash (md5/sha1/sha256/sha512/ntlm): ");
    scanf("%9s", hash_type_str);
    
    HashType hash_type = get_hash_type(hash_type_str);
    if (hash_type == -1) {
        printf(RED "\n[!] Tipo de hash não suportado!\n" RESET);
        return;
    }
    
    unsigned char digest[MAX_HASH_LENGTH];
    char hash_str[MAX_HASH_LENGTH*2 + 1];
    
    calculate_hash(input, hash_type, digest);
    
    int hash_len = 32;
    if (hash_type == HASH_SHA512) hash_len = 64;
    else if (hash_type == HASH_NTLM) hash_len = 16;
    
    for (int i = 0; i < hash_len; i++) {
        sprintf(&hash_str[i*2], "%02x", (unsigned int)digest[i]);
    }
    
    printf("\n" GREEN "[+] Hash %s: %s\n" RESET, hash_type_str, hash_str);
}

void wordlist_generator() {
    clear_screen();
    show_banner();
    printf(BOLD "[+] GERADOR DE WORDLIST\n\n" RESET);
    printf("Esta funcionalidade está em desenvolvimento.\n");
    printf("Implementação completa incluirá:\n");
    printf("- Padrões personalizáveis\n");
    printf("- Combinações de dicionário\n");
    printf("- Suporte a regras de mutação\n");
}

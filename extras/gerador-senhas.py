import random
import string
import argparse

def gerar_senha(comprimento=12, usar_maiusculas=True, usar_minusculas=True, 
                usar_numeros=True, usar_especiais=True):
    caracteres = ''
    if usar_maiusculas:
        caracteres += string.ascii_uppercase
    if usar_minusculas:
        caracteres += string.ascii_lowercase
    if usar_numeros:
        caracteres += string.digits
    if usar_especiais:
        caracteres += string.punctuation
    
    if not caracteres:
        raise ValueError("Pelo menos um tipo de caractere deve ser selecionado")
    
    return ''.join(random.choice(caracteres) for _ in range(comprimento))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Gerador de Senhas Fortes')
    parser.add_argument('-c', '--comprimento', type=int, default=12, help='Comprimento da senha (padrão: 12)')
    parser.add_argument('--sem-maiusculas', action='store_false', dest='maiusculas', help='Excluir letras maiúsculas')
    parser.add_argument('--sem-minusculas', action='store_false', dest='minusculas', help='Excluir letras minúsculas')
    parser.add_argument('--sem-numeros', action='store_false', dest='numeros', help='Excluir números')
    parser.add_argument('--sem-especiais', action='store_false', dest='especiais', help='Excluir caracteres especiais')
    
    args = parser.parse_args()
    
    try:
        senha = gerar_senha(
            comprimento=args.comprimento,
            usar_maiusculas=args.maiusculas,
            usar_minusculas=args.minusculas,
            usar_numeros=args.numeros,
            usar_especiais=args.especiais
        )
        print(f"Senha gerada: {senha}")
    except ValueError as e:
        print(e)

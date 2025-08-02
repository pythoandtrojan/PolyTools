import os 

def banner():
    print("""
    ________________________
   |    HOLEHE SCANNER     |
   | ______________________|""")

def clear():
    os.system('clear')

def gmail(email):
    os.system('holehe {email}')

def menu():
    while True:
        try:
            banner()
            print("1. olhar email")
            print("2. exit")
            escolha = int(input("escolha: "))
            if escolha == 1:
                gmail = input("seu email: ")
                print(email(gmail))
                input("precione [enter] pra continuar")
                clear()
                continue
            elif escolha == 3:
                exit()
        
                
    

from werkzeug.security import generate_password_hash

# Solicita ao usuário para digitar a senha
senha_digitada = input("Digite a senha que você deseja usar para o Admin: ")

# Gera o hash da senha
hash_gerado = generate_password_hash(senha_digitada)

print("\n--- COPIE O HASH ABAIXO E DEFINA-O COMO UMA VARIÁVEL DE AMBIENTE CHAMADA ADMIN_PASSWORD_HASH ---")
print(hash_gerado)
print("--- FIM DO CÓDIGO ---")

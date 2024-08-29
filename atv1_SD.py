# pip install pycryptodome

from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Cipher import PKCS1_OAEP

# Geração do par de chaves RSA
key = RSA.generate(2048)
private_key = RSA.import_key(key.export_key())
public_key = RSA.import_key(key.publickey().export_key())

# Mensagens
mensagem1 = 'Esta mensagem é autenticada. Banana, maçã e melancia.'
mensagem_autenticada = mensagem1.encode('utf-8')
mensagem2 = 'Esta mensagem não é autenticada. Carro, moto e avião'
mensagem_nao_autenticada = mensagem2.encode('utf-8')

# Criar assinatura da mensagem autenticada
assinatura = pkcs1_15.new(private_key).sign(SHA256.new(mensagem_autenticada))

# Encriptar as mensagens
cipher_rsa = PKCS1_OAEP.new(public_key)
mensagem_autenticada_encriptada = cipher_rsa.encrypt(mensagem_autenticada)
mensagem_nao_autenticada_encriptada = cipher_rsa.encrypt(mensagem_nao_autenticada)

# Função para desencriptar e verificar mensagem
def desencriptar_e_verificar(mensagem_encriptada, assinatura=None):
    try:
        mensagem = PKCS1_OAEP.new(private_key).decrypt(mensagem_encriptada)
        if assinatura:
            pkcs1_15.new(public_key).verify(SHA256.new(mensagem), assinatura)
            print("Mensagem autenticada e verificada com sucesso!")
        else:
            print("Mensagem desencriptada:", mensagem.decode('UTF-8'))
    except (ValueError, TypeError) as e:
        print("Erro ao desencriptar ou verificar a mensagem:", e)

# Desencriptar e verificar as mensagens
desencriptar_e_verificar(mensagem_autenticada_encriptada, assinatura)
desencriptar_e_verificar(mensagem_nao_autenticada_encriptada)
##desencriptar_e_verificar(mensagem_nao_autenticada_encriptada,'assinatura invalida')


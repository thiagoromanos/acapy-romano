import ctypes
from ctypes import c_char, c_int, c_byte, c_bool, c_ubyte, c_uint, c_uint32, c_char_p, c_void_p, Structure, POINTER, byref, create_string_buffer, sizeof
from getpass import getpass
from aries_askar import (
    AskarError,
    AskarErrorCode,
    Entry,
    Key,
    KeyAlg,
    SeedMethod,
)

# Load the shared library
libdinamo = ctypes.CDLL('/usr/lib/libdinamo.so.4.12.0.254')

# Define constants
HOST_ADDR = "10.202.40.16"
# HOST_ADDR = "200.202.34.19"
USER_ID = "amateus"
# USER_ID = "cpqd"
USER_PWD = getpass("PASS: ")
KEY_ID = "Teste"
KEY_TYPE = 201  # ALG_3DES_168 in your specific context
FLAGS = 0x00000001 | 0x00000002 | 0x00004000  # EXPORTABLE_KEY | NO_CRYPTO | BChain keys

# Assuming these are the actual values
MAX_ADDR_LEN = 128
MAX_USR_LEN = 16
MAX_USR_PWD = 16
DEFAULT_PORT = 4433  # Replace with the actual default port value
SS_USER_PWD = 0x00000002  # Replace with the actual value
ENCRYPTED_CONN = 0x00000001  # Replace with the actual value
REMOVE_FROM_HCM = 0x00000020  # Replace with the actual value
KEY_TYPE = 9
DKP_MODE = 4
DKP_IV = 2
# Define the AUTH_PWD structure

# Define the AUTH_PWD structure
class AUTH_PWD(Structure):
    _fields_ = [("szAddr", c_char * MAX_ADDR_LEN),
                ("nPort", c_int),
                ("szUserId", c_char * MAX_USR_LEN),
                ("szPassword", c_char * MAX_USR_PWD)]

class DN_BCHAIN_KEY_INFO(Structure):
    _fields_ = [
        ("bStorageType", c_ubyte),        # BYTE
        ("dwType", c_uint),               # DWORD (unsigned long)
        ("pbBip32Ver", c_ubyte * 4),      # BYTE[4]
        ("bBip32Depth", c_ubyte),         # BYTE
        ("pbParentFingerprint", c_ubyte * 4), # BYTE[4]
        ("pbChildNumber", c_ubyte * 4),   # BYTE[4]
    ]

# Define the function prototypes
libdinamo.DInitialize.argtypes = [c_int]
libdinamo.DInitialize.restype = c_int

libdinamo.DOpenSession.argtypes = [POINTER(c_void_p), c_int, POINTER(AUTH_PWD), c_int, c_int]
libdinamo.DOpenSession.restype = c_int

libdinamo.DGenerateKey.argtypes = [c_void_p, c_char_p, c_int, c_int, POINTER(c_void_p)]
libdinamo.DGenerateKey.restype = c_int

libdinamo.DDestroyKey.argtypes = [POINTER(c_void_p), c_int]
libdinamo.DDestroyKey.restype = c_int

libdinamo.DCloseSession.argtypes = [POINTER(c_void_p), c_int]
libdinamo.DCloseSession.restype = c_int

libdinamo.DFinalize.argtypes = []
libdinamo.DFinalize.restype = None

HKEYCTX = c_void_p
DWORD = c_uint32
BYTE = c_byte

MAX_OBJ_ID_LEN = 256  # Substitua pelo valor real

def DBchainGetPubKey(hSession, bType, cszId, pbDataLen, dwReserved):
    # Allocate buffer for the public key data
    pbData = (BYTE * pbDataLen)()
    pdwDataLen = DWORD(pbDataLen)
    
    # Call the function
    result = libdinamo.DBchainGetPubKey(hSession, bType, cszId.encode('utf-8'), pbData, byref(pdwDataLen), dwReserved)
    
    # Convert the buffer to bytes
    # pbData_result = bytes(pbData[:pdwDataLen.value])
    pbData_result = bytes(bytearray(pbData)[:pdwDataLen.value])
    
    return result, pbData_result

HHASHCTX = ctypes.c_void_p
# HASH_ID = 1 # MD5
# HASH_ID = 255 # for signing
def create_hash(hSession, HASH_ID = 255):
    hHash = HHASHCTX()
    result = libdinamo.DCreateHash(hSession, HASH_ID, 0, 0, ctypes.byref(hHash))
    if result:
        raise RuntimeError(f"Falha na função DCreateHash. Código de erro: {result}")
    print("Contexto de hash criado.")
    return hHash

# Adiciona dados ao hash
def hash_data(hHash, data):
    cbData = len(data)
    result = libdinamo.DHashData(hHash, data, cbData, 0)
    if result:
        raise RuntimeError(f"Falha na função DHashData. Código de erro: {result}")
    print("Dados adicionados ao hash.")

# Obtém parâmetros do hash
def get_hash_param(hHash, param):
    buffer = (BYTE * 256)()
    cbData = DWORD(ctypes.sizeof(buffer))
    result = libdinamo.DGetHashParam(hHash, param, buffer, ctypes.byref(cbData), 0) # param 2 for get hash value
    if result:
        raise RuntimeError(f"Falha na função DGetHashParam. Código de erro: {result}")
    return bytes(bytearray(buffer)[:cbData.value])

# Destrói o contexto de hash
def destroy_hash(hHash):
    if hHash:
        libdinamo.DDestroyHash(ctypes.byref(hHash))
        print("Contexto de hash liberado.")


def derive_key(hHash,szKeyId, nAlgId):
    phKey = c_void_p()
    result = libdinamo.DDeriveKey(hHash, szKeyId, nAlgId, FLAGS, byref(phKey))
    print(result)
    return result

# Sign the hash
def sign_hash(hHash, hKey,):
    # Determine the size of the signature
    cbSignature = DWORD(0)
    result = libdinamo.DSignHash(hHash, hKey, 0, cbSignature, ctypes.byref(cbSignature))
    if result and result != 1 and result != 1005:  # Assuming 1 indicates a size retrieval, adjust as needed
        raise RuntimeError(f"Failed to get signature size. Error code: {result}")

    # Allocate memory for the signature
    pbSignature = (BYTE * cbSignature.value)()

    # Generate the signature
    result = libdinamo.DSignHash(hHash, hKey, 0, pbSignature, ctypes.byref(cbSignature))

    if result:
        raise RuntimeError(f"Failed to sign hash. Error code: {result}")
    
    print("Hash signed.")
    return bytes(bytearray(pbSignature)[:cbSignature.value])
# Função helper para converter diferentes tipos de dados para byte array
def prepare_pbData(dwParam, pbData):
    if dwParam == DKP_MODE:
        # Caso DKP_MODE, pbData é um DWORD (geralmente 4 bytes)
        pbData_array = (DWORD * 1)(DWORD(pbData))
        pbData_len = ctypes.sizeof(DWORD)
    else:
        # Para outros casos, como um array de bytes (ex: DKP_IV)
        pbData_len = len(pbData)
        pbData_array = (BYTE * pbData_len)(*pbData)   
        pbData_len = len(pbData_array)     
    
    return pbData_array, pbData_len

# Função wrapper Python
def set_key_param(hKey, dwParam, pbData, dwFlags=0):
    # Preparando os dados (pbData e tamanho correto)
    pbData_array, pbData_len = prepare_pbData(dwParam, pbData)
    print(pbData_len)
    # Chamada para a função da biblioteca
    result = libdinamo.DSetKeyParam(
        hKey,
        DWORD(dwParam),
        pbData_array,
        pbData_len,
        DWORD(dwFlags)
    )
    
    if result != 0:
        raise Exception(f"Erro ao chamar DSetKeyParam, código de erro: {result}")
    
    return result

# Python function that wraps the main C function
def main():
    nRet = libdinamo.DInitialize(0)
    if nRet:
        print(f"Falha na funcao: DInitialize \nCodigo de erro: {nRet}")
        return nRet

    print("Bibliotecas inicializadas.")

    authPwd = AUTH_PWD()
    authPwd.szAddr = (HOST_ADDR + '\0' * (MAX_ADDR_LEN - len(HOST_ADDR))).encode('utf-8')
    authPwd.nPort = DEFAULT_PORT
    authPwd.szUserId = (USER_ID + '\0' * (MAX_USR_LEN - len(USER_ID))).encode('utf-8')
    authPwd.szPassword = (USER_PWD + '\0' * (MAX_USR_PWD - len(USER_PWD))).encode('utf-8')

    hSession = c_void_p()
    nRet = libdinamo.DOpenSession(byref(hSession), SS_USER_PWD, byref(authPwd), ctypes.sizeof(authPwd), ENCRYPTED_CONN)
    if nRet:
        print(f"Falha na funcao: DOpenSession \nCodigo de erro: {nRet}")
        return nRet
    # DGetUserKey
    print("Sessao com o Dinamo estabelecida.")
    hKey = c_void_p()
    MODE_GCM = (1 << 5)
    # nRet = libdinamo.DGenerateKey(hSession, KEY_ID.encode('utf-8'), KEY_TYPE, 0x00000001 | 0x00000002, byref(hKey))
    # if nRet:
    #     print(f"Falha na funcao: DGenerateKey \nCodigo de erro: {nRet}")
    #     return nRet
    # Exemplo de uso da função
    dwParam = DKP_MODE  # Parâmetro de operação
    dwOpMode = MODE_GCM  # Modo GCM para criptografia
    pbData = dwOpMode        

    # try:
    #     set_key_param(hKey, dwParam, pbData)
    #     print("Parâmetro de chave definido com sucesso!")              
    #     dwParam = DKP_IV    
    #     pbData = b'\x16D3N\x17\x19\x98\x05\xe6b\x05F\x06\xfc[6'
    #     set_key_param(hKey, dwParam, pbData)
    #     print("Parâmetro de chave definido com sucesso!")
    # except Exception as e:
    #     print(e)    
    libdinamo.DGetUserKey(hSession, KEY_ID.encode(), 0, byref(hKey))

    pbData = (BYTE * 256)()
    input_data = b"Algo legal a ser criptografado"
    cbData = DWORD(len(input_data) + 1)
    ctypes.memmove(pbData, input_data, cbData.value)

    nRet = libdinamo.DEncrypt(hKey, 0, 1, 0, pbData, byref(cbData), 256)
    if nRet:
        print("Error", nRet)
    print(f">>> {bytearray(pbData)[:cbData.value]}")
    libdinamo.DDecrypt(hKey, 0, 1, 0, pbData, byref(cbData))
    print(bytes(bytearray(pbData)[:cbData.value]).decode())
    # nRet = libdinamo.DDestroyKey(hKey, REMOVE_FROM_HCM)
    # if nRet:
    #     print("Error ao remover chave ", nRet)

    libdinamo.DFinalize()
    print("Bibliotecas finalizada.")

    return nRet

# Run the main function
if __name__ == "__main__":
    main()


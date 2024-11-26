# Generar claves públicas y privadas
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# Generar clave privada
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)

# Extraer clave pública
public_key = private_key.public_key()

# Guardar clave privada en un archivo
with open("private_key.pem", "wb") as f:
    f.write(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
    )

# Guardar clave pública en un archivo
with open("public_key.pem", "wb") as f:
    f.write(
        public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )

print("Claves generadas y guardadas en 'private_key.pem' y 'public_key.pem'")

# Crear la firma digital
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

# Leer el contenido del archivo de texto a firmar
with open("documento.txt", "rb") as f:
    message = f.read()

# Leer la clave privada
with open("private_key.pem", "rb") as f:
    private_key = serialization.load_pem_private_key(
        f.read(),
        password=None,
        backend=default_backend()
    )

# Crear la firma digital
signature = private_key.sign(
    message,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)

# Guardar la firma en un archivo
with open("signature.sig", "wb") as f:
    f.write(signature)

print("Firma digital creada y guardada en 'signature.sig'")

# Verificar la firma digital
# Leer la clave pública
with open("public_key.pem", "rb") as f:
    public_key = serialization.load_pem_public_key(
        f.read(),
        backend=default_backend()
    )

# Leer el documento y la firma
with open("documento.txt", "rb") as f:
    original_message = f.read()

with open("signature.sig", "rb") as f:
    signature = f.read()

# Verificar la firma
try:
    public_key.verify(
        signature,
        original_message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    print("¡Firma verificada con éxito! El documento no ha sido alterado.")
except Exception as e:
    print("Error de verificación: El documento o la firma no coinciden.")

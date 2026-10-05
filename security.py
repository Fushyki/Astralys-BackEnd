import os
import re
import html
import bcrypt
import jwt
import hashlib
from datetime import datetime, timedelta, timezone
from typing import Optional

# ==========================================
# CONFIGURAÇÕES JWT E SEGREDOS CRIPTOGRÁFICOS
# ==========================================
SECRET_KEY = os.getenv("SECRET_KEY", "segredo-super-secreto-ms-identity")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 60 * 24))

# Hash bcrypt pré-computado para mitigação de ataques de temporização (Timing Attacks)
DUMMY_PASSWORD_HASH = "$2b$12$K89Igh6w6.wBq1Y6UvVb1uX/Xm8z4R0pM2U5bV3L1oX.y5L4n0o1r"

# Lista de senhas comuns/fracas proibidas pelo padrão NIST
COMMON_WEAK_PASSWORDS = {
    "12345678", "123456789", "1234567890", "password", "password123",
    "admin123", "qwertyuiop", "senha123", "mudar123", "teste123",
    "iloveyou", "master123", "genshin123", "astralys123"
}


# ==========================================
# VALIDAÇÃO DE SEGURANÇA E COMPLEXIDADE (NIST)
# ==========================================

def validate_password_strength(password: str) -> None:
    """
    Valida a complexidade da senha conforme diretrizes NIST 800-63B:
    - Mínimo de 8 caracteres e máximo de 128
    - Pelo menos 1 letra maiúscula
    - Pelo menos 1 letra minúscula
    - Pelo menos 1 dígito numérico
    - Pelo menos 1 caractere especial
    - Bloqueio estrito de senhas vazadas/comuns
    """
    if len(password) < 8:
        raise ValueError("A senha deve conter no mínimo 8 caracteres.")
    if len(password) > 128:
        raise ValueError("A senha não pode exceder 128 caracteres.")
    if password.lower() in COMMON_WEAK_PASSWORDS:
        raise ValueError("Esta senha é muito comum e fraca. Escolha uma senha mais segura.")
    if not re.search(r"[A-Z]", password):
        raise ValueError("A senha deve conter pelo menos uma letra maiúscula.")
    if not re.search(r"[a-z]", password):
        raise ValueError("A senha deve conter pelo menos uma letra minúscula.")
    if not re.search(r"[0-9]", password):
        raise ValueError("A senha deve conter pelo menos um número.")
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>\-_+=\\/\\[\\]]", password):
        raise ValueError("A senha deve conter pelo menos um caractere especial (!@#$%^&*...).")


def sanitize_text(text: Optional[str]) -> Optional[str]:
    """Sanitiza strings de entrada contra ataques de XSS (Cross-Site Scripting)."""
    if text is None:
        return None
    # Converte caracteres perigosos como <, >, &, ", ' em entidades seguras
    return html.escape(text.strip())


# ==========================================
# CRIPTOGRAFIA DE SENHAS (BCRYPT)
# ==========================================

def hash_password(password: str) -> str:
    """Gera o hash com salt para armazenar a senha com segurança máxima (Bcrypt)."""
    salt = bcrypt.gensalt(rounds=12)
    hashed = bcrypt.hashpw(password.encode("utf-8"), salt)
    return hashed.decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Compara a senha digitada pelo usuário com o hash salvo no banco de forma segura."""
    try:
        return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))
    except Exception:
        return False


def verify_dummy_password(plain_password: str) -> None:
    """Executa um hash Bcrypt simulado em tempo constante para neutralizar Timing Attacks."""
    try:
        bcrypt.checkpw(plain_password.encode("utf-8"), DUMMY_PASSWORD_HASH.encode("utf-8"))
    except Exception:
        pass


# ==========================================
# GERAÇÃO E VALIDAÇÃO DE TOKENS JWT
# ==========================================

def hash_token(token: str) -> str:
    """Gera uma impressão digital (hash SHA-256) do token para auditoria e revogação."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Gera um token JWT com expiração e claims seguros."""
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (
        expires_delta if expires_delta else timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode.update({
        "exp": expire,
        "iat": datetime.now(timezone.utc),
        "iss": "astralys-ametist-sso"
    })
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def decode_access_token(token: str) -> Optional[dict]:
    """Decodifica e valida a assinatura criptográfica e a expiração do token JWT."""
    try:
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM],
            options={"require": ["exp", "sub", "iat"]}
        )
        return payload
    except jwt.PyJWTError:
        return None
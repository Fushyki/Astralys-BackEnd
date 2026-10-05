import bcrypt
import jwt
import hashlib
from datetime import datetime, timedelta, timezone
from typing import Optional

# ==========================================
# CONFIGURAÇÕES JWT
# ==========================================
SECRET_KEY = "segredo-super-secreto-ms-identity"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24  # 1 dia (24 horas)


# ==========================================
# CRIPTOGRAFIA DE SENHAS (BCRYPT)
# ==========================================

def hash_password(password: str) -> str:
    """Gera o hash com salt para armazenar a senha com segurança."""
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode("utf-8"), salt)
    return hashed.decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Compara a senha digitada pelo usuário com o hash salvo no banco."""
    return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))


# ==========================================
# GERAÇÃO E VALIDAÇÃO DE TOKENS JWT
# ==========================================

def hash_token(token: str) -> str:
    """Gera uma impressão digital (hash SHA-256) do token para a tabela sessoes_ativas."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Gera um token JWT com expiração."""
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (
        expires_delta if expires_delta else timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def decode_access_token(token: str) -> Optional[dict]:
    """Decodifica e valida o token JWT. Retorna None se estiver inválido ou expirado."""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.PyJWTError:
        return None
import json
from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator
from datetime import datetime
from typing import Optional, Dict, Any, List
import security

MAX_PROJECT_JSON_BYTES = 1_000_000  # ~1 MB por projeto
MAX_SYNC_ITEMS = 100


def _validate_https_url(v: Optional[str]) -> Optional[str]:
    """Aceita apenas URLs http(s); bloqueia esquemas como javascript: ou data:."""
    if v is None or v == "":
        return v
    if not (v.startswith("https://") or v.startswith("http://")):
        raise ValueError("A URL deve começar com http:// ou https://.")
    return v

class UsuarioCreate(BaseModel):
    nome: str = Field(..., min_length=2, max_length=100, description="Nome do usuário")
    email: EmailStr = Field(..., description="E-mail válido")
    senha: str = Field(..., min_length=8, max_length=128, description="Senha forte conforme padrão NIST")

    @field_validator('nome')
    @classmethod
    def sanitize_user_name(cls, v: str) -> str:
        return security.sanitize_text(v) or v

    @field_validator('senha')
    @classmethod
    def validate_password(cls, v: str) -> str:
        security.validate_password_strength(v)
        return v

class LoginRequest(BaseModel):
    email: EmailStr
    senha: str = Field(..., min_length=1, max_length=128)

class OAuthSyncRequest(BaseModel):
    """O e-mail NÃO vem daqui: é lido do token do provedor (verificado no servidor)."""
    nome: Optional[str] = Field(None, min_length=1, max_length=100, description="Nome do perfil Google (opcional)")
    avatar_url: Optional[str] = Field(None, max_length=500, description="URL da foto do perfil Google")
    provider: Optional[str] = Field("google", max_length=50)

    @field_validator('nome')
    @classmethod
    def sanitize_oauth_name(cls, v: Optional[str]) -> Optional[str]:
        return security.sanitize_text(v)

    @field_validator('avatar_url')
    @classmethod
    def validate_oauth_avatar(cls, v: Optional[str]) -> Optional[str]:
        return _validate_https_url(v)


class AlterarSenhaRequest(BaseModel):
    senha_atual: str = Field(..., min_length=1, max_length=128, description="Senha atual para confirmação")
    nova_senha: str = Field(..., min_length=8, max_length=128, description="Nova senha forte")

    @field_validator('nova_senha')
    @classmethod
    def validate_new_password(cls, v: str) -> str:
        security.validate_password_strength(v)
        return v

class UsuarioUpdate(BaseModel):
    nome: Optional[str] = Field(None, min_length=2, max_length=100)
    avatar_url: Optional[str] = Field(None, max_length=500)
    status_recado: Optional[str] = Field(None, max_length=255)

    @field_validator('nome')
    @classmethod
    def sanitize_update_name(cls, v: Optional[str]) -> Optional[str]:
        return security.sanitize_text(v)

    @field_validator('avatar_url')
    @classmethod
    def validate_update_avatar(cls, v: Optional[str]) -> Optional[str]:
        return _validate_https_url(v)

    @field_validator('status_recado')
    @classmethod
    def sanitize_update_recado(cls, v: Optional[str]) -> Optional[str]:
        return security.sanitize_text(v)

class UsuarioResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    email: str
    nome: str
    avatar_url: Optional[str] = None
    status_recado: Optional[str] = None
    criado_em: datetime

class PerfilPublico(BaseModel):
    """Perfil visível para outros usuários: sem e-mail."""
    model_config = ConfigDict(from_attributes=True)
    id: str
    nome: str
    avatar_url: Optional[str] = None
    status_recado: Optional[str] = None

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    usuario: UsuarioResponse

class MensagemResponse(BaseModel):
    mensagem: str

class SsoTicketResponse(BaseModel):
    ticket: str
    expires_in: int = 60

class SsoExchangeRequest(BaseModel):
    ticket: str = Field(..., min_length=10, max_length=128, description="Ticket efêmero de uso único")

# ==========================================
# SCHEMAS DO ASTRALYS (PROJETOS & CÁLCULOS)
# ==========================================

def _check_project_size(v: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if v is not None and len(json.dumps(v, ensure_ascii=False)) > MAX_PROJECT_JSON_BYTES:
        raise ValueError("O projeto excede o tamanho máximo permitido (1 MB).")
    return v


class ProjetoCalculoCreate(BaseModel):
    id: Optional[str] = Field(None, max_length=36)
    nome: str = Field(..., min_length=1, max_length=255, description="Nome do projeto de cálculo")
    character_name: str = Field(..., min_length=1, max_length=100, description="Personagem principal")
    role: Optional[str] = Field("Main DPS", max_length=50)
    version: Optional[str] = Field("1.0", max_length=20)
    author: Optional[str] = Field("Astralys", max_length=100)
    dados: Dict[str, Any] = Field(..., description="Conteúdo completo da planilha, rotação e métricas")
    is_public: Optional[bool] = False

    @field_validator('nome')
    @classmethod
    def sanitize_proj_nome(cls, v: str) -> str:
        return security.sanitize_text(v) or v

    @field_validator('character_name')
    @classmethod
    def sanitize_char_nome(cls, v: str) -> str:
        return security.sanitize_text(v) or v

    @field_validator('dados')
    @classmethod
    def limit_dados_size(cls, v: Dict[str, Any]) -> Dict[str, Any]:
        return _check_project_size(v)

class ProjetoCalculoUpdate(BaseModel):
    nome: Optional[str] = None
    character_name: Optional[str] = None
    role: Optional[str] = None
    version: Optional[str] = None
    author: Optional[str] = None
    dados: Optional[Dict[str, Any]] = None
    is_public: Optional[bool] = None

    @field_validator('nome')
    @classmethod
    def sanitize_update_proj_nome(cls, v: Optional[str]) -> Optional[str]:
        return security.sanitize_text(v)

    @field_validator('dados')
    @classmethod
    def limit_update_dados_size(cls, v: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        return _check_project_size(v)

class ProjetoCalculoResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    usuario_id: str
    nome: str
    character_name: str
    role: str
    version: str
    author: str
    dados: Dict[str, Any]
    is_public: bool
    criado_em: datetime
    atualizado_em: datetime

class ProjetoResumo(BaseModel):
    """Versão leve para listagens públicas: sem o JSON completo do projeto."""
    model_config = ConfigDict(from_attributes=True)
    id: str
    nome: str
    character_name: str
    role: str
    version: str
    author: str
    criado_em: datetime
    atualizado_em: datetime

class ProjetoSyncRequest(BaseModel):
    projetos: List[ProjetoCalculoCreate] = Field(..., max_length=MAX_SYNC_ITEMS)
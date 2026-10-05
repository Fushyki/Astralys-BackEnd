from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator
from datetime import datetime
from typing import Optional, Dict, Any, List
import security

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

class ProjetoCalculoCreate(BaseModel):
    id: Optional[str] = None
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

class ProjetoSyncRequest(BaseModel):
    projetos: List[ProjetoCalculoCreate]
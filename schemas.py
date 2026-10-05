from pydantic import BaseModel, ConfigDict, EmailStr, Field
from datetime import datetime
from typing import Optional, Dict, Any, List

class UsuarioCreate(BaseModel):
    nome: str = Field(..., min_length=2, max_length=100, description="Nome do usuário")
    email: EmailStr = Field(..., description="E-mail válido")
    senha: str = Field(..., min_length=6, description="Senha com no mínimo 6 caracteres")

class LoginRequest(BaseModel):
    email: EmailStr
    senha: str

class AlterarSenhaRequest(BaseModel):
    senha_atual: str = Field(..., description="Senha atual para confirmação")
    nova_senha: str = Field(..., min_length=6, description="Nova senha com no mínimo 6 caracteres")

class UsuarioUpdate(BaseModel):
    nome: Optional[str] = Field(None, min_length=2, max_length=100)
    avatar_url: Optional[str] = None
    status_recado: Optional[str] = Field(None, max_length=255)

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

# ==========================================
# SCHEMAS DO ASTRALYS (PROJETOS & CÁLCULOS)
# ==========================================

class ProjetoCalculoCreate(BaseModel):
    id: Optional[str] = None
    nome: str = Field(..., min_length=1, max_length=255, description="Nome do projeto de cálculo")
    character_name: str = Field(..., max_length=100, description="Personagem principal")
    role: Optional[str] = Field("Main DPS", max_length=50)
    version: Optional[str] = Field("1.0", max_length=20)
    author: Optional[str] = Field("Astralys", max_length=100)
    dados: Dict[str, Any] = Field(..., description="Conteúdo completo da planilha, rotação e métricas")
    is_public: Optional[bool] = False

class ProjetoCalculoUpdate(BaseModel):
    nome: Optional[str] = None
    character_name: Optional[str] = None
    role: Optional[str] = None
    version: Optional[str] = None
    author: Optional[str] = None
    dados: Optional[Dict[str, Any]] = None
    is_public: Optional[bool] = None

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
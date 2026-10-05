import uuid
from datetime import datetime
from sqlalchemy import Column, String, Boolean, DateTime, ForeignKey, JSON
from sqlalchemy.orm import relationship
from database import Base


class Usuario(Base):
    __tablename__ = "usuarios"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    email = Column(String(255), unique=True, index=True, nullable=False)
    nome = Column(String(255), nullable=False)
    avatar_url = Column(String(500), nullable=True)
    status_recado = Column(String(255), default="Olá! Estou usando o chat.")
    criado_em = Column(DateTime, default=datetime.utcnow)
    atualizado_em = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    credencial = relationship("Credencial", back_populates="usuario", uselist=False, cascade="all, delete-orphan")
    sessoes = relationship("SessaoAtiva", back_populates="usuario", cascade="all, delete-orphan")
    projetos = relationship("ProjetoCalculo", back_populates="usuario", cascade="all, delete-orphan")

class Credencial(Base):
    __tablename__ = "credenciais"
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    usuario_id = Column(String(36), ForeignKey("usuarios.id"), unique=True, nullable=False)
    senha_hash = Column(String(255), nullable=False)
    ultimo_login = Column(DateTime, nullable=True)

    usuario = relationship("Usuario", back_populates="credencial")

class SessaoAtiva(Base):
    __tablename__ = "sessoes_ativas"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    usuario_id = Column(String(36), ForeignKey("usuarios.id"), nullable=False)
    refresh_token_hash = Column(String(255), nullable=False)
    expira_em = Column(DateTime, nullable=False)
    revogado = Column(Boolean, default=False)

    usuario = relationship("Usuario", back_populates="sessoes")

class ProjetoCalculo(Base):
    __tablename__ = "astralys_projetos"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    usuario_id = Column(String(36), ForeignKey("usuarios.id", ondelete="CASCADE"), nullable=False, index=True)
    nome = Column(String(255), nullable=False)
    character_name = Column(String(100), nullable=False)
    role = Column(String(50), default="Main DPS")
    version = Column(String(20), default="1.0")
    author = Column(String(100), default="Astralys")
    dados = Column(JSON, nullable=False)
    is_public = Column(Boolean, default=False)
    criado_em = Column(DateTime, default=datetime.utcnow)
    atualizado_em = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    usuario = relationship("Usuario", back_populates="projetos")
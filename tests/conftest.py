"""Configuração dos testes: banco SQLite temporário e segredos de teste, definidos ANTES de importar a app."""
import os
import sys
import tempfile
import uuid
from pathlib import Path

_TMP = tempfile.mkdtemp(prefix="astralys_tests_")
os.environ["DATABASE_URL"] = f"sqlite:///{Path(_TMP, 'teste.db').as_posix()}"
os.environ["SECRET_KEY"] = "chave-de-teste-" + "x" * 40
os.environ["SUPABASE_JWT_SECRET"] = "supabase-segredo-de-teste-" + "y" * 40

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest
from fastapi.testclient import TestClient

import main  # noqa: E402


@pytest.fixture()
def client():
    # O limitador de login é por IP; os testes partilham o mesmo IP, então zeramos entre testes.
    main.auth_rate_limiter.history.clear()
    main.general_rate_limiter.history.clear()
    with TestClient(main.app) as c:
        yield c


def limpar_limites():
    main.auth_rate_limiter.history.clear()
    main.general_rate_limiter.history.clear()


SENHA = "Senha-Forte#2024"


def criar_usuario(client, nome="Davi", email=None):
    """Registra e faz login. Devolve (token, perfil). Sem e-mail, gera um único (o banco é partilhado)."""
    email = email or f"{uuid.uuid4().hex[:12]}@exemplo.com"
    limpar_limites()
    r = client.post("/auth/register", json={"nome": nome, "email": email, "senha": SENHA})
    assert r.status_code == 201, r.text
    limpar_limites()
    r = client.post("/auth/login", json={"email": email, "senha": SENHA})
    assert r.status_code == 200, r.text
    corpo = r.json()
    return corpo["access_token"], corpo["usuario"]


def auth(token):
    return {"Authorization": f"Bearer {token}"}

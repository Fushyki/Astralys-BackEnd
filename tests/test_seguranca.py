"""Testes das correções de segurança da v2."""
import subprocess
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import jwt

import security
from conftest import SENHA, auth, criar_usuario, limpar_limites

RAIZ = Path(__file__).resolve().parent.parent


# ---------- SECRET_KEY ----------

def _importar_security_com_env(env_extra):
    import os
    env = {k: v for k, v in os.environ.items() if k != "SECRET_KEY"}
    env.update(env_extra)
    return subprocess.run(
        [sys.executable, "-c", "import security"],
        cwd=RAIZ, env=env, capture_output=True, text=True,
    )


def test_nao_arranca_sem_secret_key():
    r = _importar_security_com_env({})
    assert r.returncode != 0
    assert "SECRET_KEY" in r.stderr


def test_nao_arranca_com_segredo_padrao_publico():
    r = _importar_security_com_env({"SECRET_KEY": "segredo-super-secreto-ms-identity"})
    assert r.returncode != 0


def test_nao_arranca_com_segredo_curto():
    r = _importar_security_com_env({"SECRET_KEY": "curto"})
    assert r.returncode != 0


# ---------- Sessão e JWT ----------

def test_jwt_valido_sem_sessao_registrada_e_rejeitado(client):
    _, perfil = criar_usuario(client)
    # Token assinado com a chave certa, mas que nunca foi emitido pelo login (sem linha em sessoes_ativas)
    # O jti garante que não é byte a byte igual ao token do login (que tem as mesmas claims no mesmo segundo)
    forjado = security.create_access_token({"sub": perfil["id"], "email": perfil["email"], "jti": uuid.uuid4().hex})
    r = client.get("/usuarios/me", headers=auth(forjado))
    assert r.status_code == 401


def test_jwt_com_issuer_errado_e_rejeitado(client):
    _, perfil = criar_usuario(client)
    agora = datetime.now(timezone.utc)
    token = jwt.encode(
        {"sub": perfil["id"], "email": perfil["email"], "iat": agora,
         "exp": agora + timedelta(hours=1), "iss": "outro-emissor"},
        security.SECRET_KEY, algorithm=security.ALGORITHM,
    )
    assert security.decode_access_token(token) is None


def test_logout_revoga_a_sessao(client):
    token, _ = criar_usuario(client)
    assert client.get("/usuarios/me", headers=auth(token)).status_code == 200
    assert client.post("/auth/logout", headers=auth(token)).status_code == 200
    assert client.get("/usuarios/me", headers=auth(token)).status_code == 401


def test_trocar_senha_invalida_as_sessoes(client):
    token, _ = criar_usuario(client)
    r = client.put("/auth/alterar-senha", headers=auth(token),
                   json={"senha_atual": SENHA, "nova_senha": "Outra-Senha#2025"})
    assert r.status_code == 200
    assert client.get("/usuarios/me", headers=auth(token)).status_code == 401


# ---------- oauth-sync ----------

def test_oauth_sync_sem_token_nao_cria_sessao(client):
    # Antes da correção, bastava enviar o e-mail da vítima para receber o token dela.
    limpar_limites()
    r = client.post("/auth/oauth-sync", json={"email": "vitima@exemplo.com", "nome": "Vitima"})
    assert r.status_code in (401, 403)
    assert "access_token" not in r.text


def test_oauth_sync_com_token_de_outro_segredo_e_rejeitado(client):
    limpar_limites()
    falso = jwt.encode(
        {"sub": "x", "email": "vitima@exemplo.com", "aud": "authenticated",
         "exp": datetime.now(timezone.utc) + timedelta(hours=1)},
        "segredo-errado-" + "z" * 40, algorithm="HS256",
    )
    r = client.post("/auth/oauth-sync", headers=auth(falso), json={"nome": "Vitima"})
    assert r.status_code == 401


def test_oauth_sync_usa_o_email_do_token_e_ignora_o_corpo(client):
    import os
    limpar_limites()
    valido = jwt.encode(
        {"sub": str(uuid.uuid4()), "email": "Real@Exemplo.com", "aud": "authenticated",
         "user_metadata": {"full_name": "Pessoa Real"},
         "exp": datetime.now(timezone.utc) + timedelta(hours=1)},
        os.environ["SUPABASE_JWT_SECRET"], algorithm="HS256",
    )
    # O corpo tenta se passar por outra conta; o servidor só pode confiar no token.
    r = client.post("/auth/oauth-sync", headers=auth(valido),
                    json={"email": "vitima@exemplo.com", "nome": "Pessoa Real"})
    assert r.status_code == 200, r.text
    assert r.json()["usuario"]["email"] == "real@exemplo.com"


def test_oauth_sync_desligado_sem_segredo_do_supabase(client, monkeypatch):
    monkeypatch.delenv("SUPABASE_JWT_SECRET", raising=False)
    limpar_limites()
    r = client.post("/auth/oauth-sync", headers=auth("qualquer"), json={})
    assert r.status_code == 503


# ---------- Perfis ----------

def test_listar_usuarios_exige_login_e_nao_expoe_email(client):
    token, _ = criar_usuario(client, "Ana", "ana@exemplo.com")
    assert client.get("/usuarios").status_code in (401, 403)

    r = client.get("/usuarios", headers=auth(token))
    assert r.status_code == 200
    assert r.json(), "deveria listar pelo menos o próprio usuário"
    assert all("email" not in u for u in r.json())


def test_perfil_por_id_exige_login(client):
    token, perfil = criar_usuario(client, "Bia", "bia@exemplo.com")
    assert client.get(f"/usuarios/{perfil['id']}").status_code in (401, 403)
    r = client.get(f"/usuarios/{perfil['id']}", headers=auth(token))
    assert r.status_code == 200 and "email" not in r.json()


def test_avatar_com_esquema_perigoso_e_rejeitado(client):
    token, _ = criar_usuario(client, "Caio", "caio@exemplo.com")
    r = client.put("/usuarios/me", headers=auth(token), json={"avatar_url": "javascript:alert(1)"})
    assert r.status_code == 422


# ---------- Projetos ----------

def _projeto(**extra):
    base = {"nome": "Mavuika Combo", "character_name": "Mavuika", "dados": {"schemaVersion": 1}}
    base.update(extra)
    return base


def test_id_de_projeto_de_outro_usuario_da_409_e_nao_500(client):
    ta, _ = criar_usuario(client, "Alice", "a@exemplo.com")
    tb, _ = criar_usuario(client, "Bruno", "b@exemplo.com")
    pid = str(uuid.uuid4())
    assert client.post("/astralys/projetos", headers=auth(ta), json=_projeto(id=pid)).status_code == 201
    r = client.post("/astralys/projetos", headers=auth(tb), json=_projeto(id=pid))
    assert r.status_code == 409


def test_sync_ignora_id_alheio_sem_derrubar_o_lote(client):
    ta, _ = criar_usuario(client, "Alice", "a2@exemplo.com")
    tb, _ = criar_usuario(client, "Bruno", "b2@exemplo.com")
    pid = str(uuid.uuid4())
    client.post("/astralys/projetos", headers=auth(ta), json=_projeto(id=pid, nome="De A"))

    r = client.post("/astralys/projetos/sync", headers=auth(tb), json={
        "projetos": [_projeto(id=pid, nome="Tentativa de B"), _projeto(nome="Legitimo de B")]
    })
    assert r.status_code == 200, r.text
    nomes = [p["nome"] for p in r.json()]
    assert nomes == ["Legitimo de B"]

    # O projeto de A continua intacto
    original = client.get(f"/astralys/projetos/{pid}", headers=auth(ta)).json()
    assert original["nome"] == "De A"


def test_autor_vem_do_servidor_e_nao_do_cliente(client):
    token, perfil = criar_usuario(client, "Dani", "dani@exemplo.com")
    r = client.post("/astralys/projetos", headers=auth(token), json=_projeto(author="Administrador Falso"))
    assert r.status_code == 201
    assert r.json()["author"] == perfil["nome"]


def test_projeto_privado_de_outro_usuario_da_403(client):
    ta, _ = criar_usuario(client, "Alice", "a3@exemplo.com")
    tb, _ = criar_usuario(client, "Bruno", "b3@exemplo.com")
    pid = client.post("/astralys/projetos", headers=auth(ta), json=_projeto()).json()["id"]
    assert client.get(f"/astralys/projetos/{pid}", headers=auth(tb)).status_code == 403
    assert client.put(f"/astralys/projetos/{pid}", headers=auth(tb), json={"nome": "x"}).status_code == 404
    assert client.delete(f"/astralys/projetos/{pid}", headers=auth(tb)).status_code == 404


def test_listagem_publica_e_resumida_e_paginada(client):
    token, _ = criar_usuario(client, "Edu", "edu@exemplo.com")
    for i in range(3):
        client.post("/astralys/projetos", headers=auth(token), json=_projeto(nome=f"P{i}", is_public=True))
    r = client.get("/astralys/projetos/publicos?limit=2")
    assert r.status_code == 200
    assert len(r.json()) == 2
    assert all("dados" not in p and "usuario_id" not in p for p in r.json())


def test_projeto_acima_de_1mb_e_rejeitado(client):
    token, _ = criar_usuario(client, "Fabi", "fabi@exemplo.com")
    enorme = {"lixo": "x" * 1_100_000}
    r = client.post("/astralys/projetos", headers=auth(token), json=_projeto(dados=enorme))
    assert r.status_code == 422


# ---------- Rate limit ----------

def test_ip_forjado_no_inicio_do_xff_nao_contorna_o_limite(client):
    """A app usa a ÚLTIMA entrada do X-Forwarded-For (a do proxy confiável); a primeira é forjável."""
    limpar_limites()
    codigos = []
    for i in range(8):
        r = client.post("/auth/login",
                        json={"email": "ninguem@exemplo.com", "senha": "qualquer"},
                        headers={"X-Forwarded-For": f"10.0.0.{i}, 203.0.113.9"})
        codigos.append(r.status_code)
    assert 429 in codigos

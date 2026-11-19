"""Galeria de times publicados sem conta: publicar, buscar, ler e despublicar com o token."""
import main

TIME = {
    "nome": "Mavuika Iansan", "author": "Davi", "version": "5.8", "members": ["Mavuika", "Iansan"],
    "resumo": {"dps": 100000, "dpr": 900000, "moves": ["Ataque", "Skill"]}, "dados": {"x": 1},
}


def publicar(client, **mudancas):
    r = client.post("/times", json={**TIME, **mudancas})
    assert r.status_code == 201, r.text
    return r.json()


def test_publica_sem_login_busca_le_e_remove(client):
    c = publicar(client)
    assert client.get("/times", params={"personagem": "mavuika"}).json()[0]["id"] == c["id"]
    assert client.get("/times", params={"q": "iansan"}).json()[0]["id"] == c["id"]
    assert client.get("/times", params={"personagem": "Xiangling"}).json() == []
    assert client.get("/times", params={"versao": "5.7"}).json() == []
    assert client.get(f"/times/{c['id']}").json()["dados"] == {"x": 1}
    assert "dados" not in client.get("/times").json()[0]
    assert "edit_token" not in client.get("/times").text and "hash" not in client.get(f"/times/{c['id']}").text
    assert client.delete(f"/times/{c['id']}", headers={"X-Edit-Token": "errado"}).status_code == 403
    assert client.delete(f"/times/{c['id']}", headers={"X-Edit-Token": c["edit_token"]}).status_code == 200
    assert client.get(f"/times/{c['id']}").status_code == 404


def test_valida_entrada_e_limita_publicacoes(client):
    assert client.post("/times", json={**TIME, "members": []}).status_code == 422
    assert client.post("/times", json={**TIME, "nome": "   "}).status_code == 422
    assert client.post("/times", json={**TIME, "resumo": {"a": "x" * 30000}}).status_code == 422
    main.publish_rate_limiter.history.clear()
    for _ in range(10):
        publicar(client)
    assert client.post("/times", json=TIME).status_code == 429
    main.publish_rate_limiter.history.clear()


def test_admin_remove_qualquer_time_e_so_com_token_forte(client, monkeypatch):
    c = publicar(client)
    main.admin_fail_limiter.history.clear()
    monkeypatch.setenv("ADMIN_TOKEN", "curto")
    assert client.delete(f"/times/{c['id']}", headers={"X-Admin-Token": "curto"}).status_code == 403
    forte = "a" * 40
    monkeypatch.setenv("ADMIN_TOKEN", forte)
    assert client.delete(f"/times/{c['id']}", headers={"X-Admin-Token": "b" * 40}).status_code == 403
    assert client.delete(f"/times/{c['id']}", headers={"X-Admin-Token": forte}).status_code == 200
    monkeypatch.delenv("ADMIN_TOKEN")
    c2 = publicar(client)
    assert client.delete(f"/times/{c2['id']}", headers={"X-Admin-Token": ""}).status_code == 403


def test_erro_repetido_no_codigo_bloqueia(client, monkeypatch):
    main.admin_fail_limiter.history.clear()
    monkeypatch.setenv("ADMIN_TOKEN", "x" * 12)
    c = publicar(client)
    for _ in range(5):
        assert client.delete(f"/times/{c['id']}", headers={"X-Admin-Token": "errado"}).status_code == 403
    assert client.delete(f"/times/{c['id']}", headers={"X-Admin-Token": "x" * 12}).status_code == 429
    main.admin_fail_limiter.history.clear()

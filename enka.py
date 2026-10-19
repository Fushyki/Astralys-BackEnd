"""Proxy do Enka.Network (a mesma fonte do akasha.cv): o navegador não consegue chamar o Enka direto (sem CORS)."""
import json
import time
import urllib.error
import urllib.request
from typing import Any, Dict, Tuple

ENKA_URL = "https://enka.network/api/uid/{uid}"
# O Enka exige um User-Agent que identifique a aplicação.
USER_AGENT = "Astralys/1.0 (+https://astralys.vercel.app)"
TIMEOUT_SECONDS = 12
CACHE_SECONDS = 60
CACHE_MAX_ENTRIES = 300

_cache: Dict[str, Tuple[float, Dict[str, Any]]] = {}


class EnkaError(Exception):
    """Erro já traduzido para o usuário: status HTTP e mensagem em português."""

    def __init__(self, status: int, mensagem: str):
        super().__init__(mensagem)
        self.status = status
        self.mensagem = mensagem


_MENSAGENS = {
    400: (400, "UID inválido."),
    404: (404, "Esse UID não existe no Enka.Network."),
    424: (503, "O jogo está em manutenção ou atualização; tente de novo mais tarde."),
    429: (429, "O Enka.Network limitou os pedidos. Espere um minuto e tente de novo."),
    500: (502, "O Enka.Network teve um erro. Tente de novo em instantes."),
    503: (503, "O Enka.Network está indisponível no momento."),
}


def _baixar(uid: str) -> Dict[str, Any]:
    pedido = urllib.request.Request(ENKA_URL.format(uid=uid), headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
    try:
        with urllib.request.urlopen(pedido, timeout=TIMEOUT_SECONDS) as resposta:
            return json.loads(resposta.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        status, mensagem = _MENSAGENS.get(e.code, (502, f"O Enka.Network respondeu com erro {e.code}."))
        raise EnkaError(status, mensagem)
    except (urllib.error.URLError, TimeoutError, OSError):
        raise EnkaError(503, "Não consegui falar com o Enka.Network. Tente de novo em instantes.")
    except ValueError:
        raise EnkaError(502, "Resposta inesperada do Enka.Network.")


def buscar(uid: str) -> Dict[str, Any]:
    """Dados da vitrine do jogador, com cache curto para não repetir pedidos ao Enka."""
    agora = time.time()
    guardado = _cache.get(uid)
    if guardado and agora - guardado[0] < CACHE_SECONDS:
        return guardado[1]
    dados = _baixar(uid)
    if len(_cache) >= CACHE_MAX_ENTRIES:
        _cache.pop(min(_cache, key=lambda k: _cache[k][0]))
    _cache[uid] = (agora, dados)
    return dados

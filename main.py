import os
import uuid
import time
from collections import defaultdict
from fastapi import FastAPI, Depends, HTTPException, status, Request, Response, Query, Path
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from typing import List
from datetime import datetime, timedelta

from database import engine, Base, get_db
import models
import schemas
import security
import enka

# Garante que as tabelas existam no banco SQL
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Ametist & Astralys - Identity, SSO & Projects Suite",
    description="Responsável por autenticação SSO JWT, perfis e sincronização de planilhas/projetos do Astralys com segurança extrema.",
    version="2.1.0"
)

# ==========================================
# 1. RATE LIMITER ANTI-BRUTE FORCE / DDOS
# ==========================================

class SlidingWindowRateLimiter:
    """Implementação em memória de janela deslizante para controle estrito de requisições por IP."""
    def __init__(self):
        self.history = defaultdict(list)

    def is_allowed(self, ip: str, max_requests: int, window_seconds: int = 60) -> bool:
        now = time.time()
        # Filtra apenas requisições dentro da janela temporal
        recentes = [t for t in self.history[ip] if now - t < window_seconds]
        if len(recentes) >= max_requests:
            self.history[ip] = recentes
            return False
        recentes.append(now)
        self.history[ip] = recentes
        # Descarta IPs inativos para o dicionário não crescer indefinidamente
        if len(self.history) > 10_000:
            for chave in [k for k, v in self.history.items() if not v or now - v[-1] >= window_seconds]:
                self.history.pop(chave, None)
        return True

auth_rate_limiter = SlidingWindowRateLimiter()
general_rate_limiter = SlidingWindowRateLimiter()

# ==========================================
# 2. MIDDLEWARE DE HEADERS DE SEGURANÇA E RATE LIMIT
# ==========================================

@app.middleware("http")
async def security_and_rate_limit_middleware(request: Request, call_next):
    # Identifica IP real (considerando proxies do Render / Cloudflare)
    forwarded = request.headers.get("x-forwarded-for")
    client_ip = forwarded.split(",")[-1].strip() if forwarded else (request.client.host if request.client else "unknown")

    path = request.url.path
    method = request.method

    # Ignora pre-flight CORS OPTIONS
    if method != "OPTIONS":
        # Limite estrito de 6 tentativas por minuto para rotas sensíveis de autenticação
        if path in ("/auth/login", "/auth/register", "/auth/alterar-senha", "/auth/sso/exchange", "/auth/sso/ticket", "/auth/oauth-sync"):
            if not auth_rate_limiter.is_allowed(client_ip, max_requests=6, window_seconds=60):
                return Response(
                    content='{"detail": "Muitas tentativas de autenticação detectadas. Por segurança, aguarde 60 segundos antes de tentar novamente."}',
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    media_type="application/json",
                    headers={"Retry-After": "60"}
                )
        else:
            # Limite geral de 150 requisições por minuto para mitigação de scraping / DDoS
            if not general_rate_limiter.is_allowed(client_ip, max_requests=150, window_seconds=60):
                return Response(
                    content='{"detail": "Limite de requisições excedido. Reduza a frequência de chamadas."}',
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    media_type="application/json",
                    headers={"Retry-After": "30"}
                )

    response = await call_next(request)

    # Injeta Headers HTTP de Segurança Máxima (OWASP Compliant)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"

    return response

# ==========================================
# 3. CORS BLINDADO (ORIGENS AUTORIZADAS)
# ==========================================

ALLOWED_ORIGINS = [
    "https://astralys.onrender.com",
    "https://ametist-tier-maker.vercel.app",
    "http://localhost:5173",
    "http://localhost:5174",
    "http://127.0.0.1:5173",
    "http://127.0.0.1:5174",
]

env_origins = os.getenv("ALLOWED_ORIGINS")
if env_origins:
    for o in env_origins.split(","):
        clean_o = o.strip()
        if clean_o and clean_o not in ALLOWED_ORIGINS:
            ALLOWED_ORIGINS.append(clean_o)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=False,  # a autenticação é por header Bearer, não por cookie
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)

security_scheme = HTTPBearer()


# ==========================================
# DEPENDÊNCIA DE AUTENTICAÇÃO E SESSÃO
# ==========================================

def get_current_user(
        credentials: HTTPAuthorizationCredentials = Depends(security_scheme),
        db: Session = Depends(get_db)
) -> models.Usuario:
    """Valida o token JWT e verifica se a sessão ainda é válida (não foi revogada no logout)."""
    token = credentials.credentials
    payload = security.decode_access_token(token)

    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token inválido ou expirado.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token sem identificação de usuário.",
        )

    # 1. Confere na tabela sessoes_ativas se não foi feito logout
    token_hash = security.hash_token(token)
    sessao = db.query(models.SessaoAtiva).filter(
        models.SessaoAtiva.refresh_token_hash == token_hash
    ).first()

    # A sessão precisa existir (um JWT válido sem sessão registrada não é aceito), não estar revogada nem expirada
    if not sessao or sessao.revogado or sessao.expira_em < datetime.utcnow() or sessao.usuario_id != user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Sessão inválida, expirada ou revogada. Faça login novamente.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # 2. Busca o perfil do usuário
    user = db.query(models.Usuario).filter(models.Usuario.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Usuário não encontrado.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


# ==========================================
# ROTA DE HEALTH CHECK
# ==========================================

@app.get("/", tags=["Saúde"])
def health_check():
    return {
        "status": "online",
        "service": "ms-identity"
    }


# ==========================================
# ENKA.NETWORK (importar builds pelo UID)
# ==========================================

@app.get("/enka/{uid}", tags=["Enka"])
def vitrine_do_jogador(uid: str = Path(..., pattern=r"^\d{9,10}$", description="UID do jogador (9 ou 10 dígitos)")):
    """Vitrine pública do jogador (personagens, armas, artefatos), vinda do Enka.Network, a mesma fonte do akasha.cv."""
    try:
        return enka.buscar(uid)
    except enka.EnkaError as e:
        raise HTTPException(status_code=e.status, detail=e.mensagem)


# ==========================================
# ROTAS DE AUTENTICAÇÃO E SESSÕES
# ==========================================

@app.post("/auth/register", response_model=schemas.UsuarioResponse, status_code=status.HTTP_201_CREATED,
          tags=["Autenticação"])
def registrar_usuario(dados: schemas.UsuarioCreate, db: Session = Depends(get_db)):
    """Cadastra um novo usuário e cria suas credenciais com senha protegida por Bcrypt."""
    usuario_existente = db.query(models.Usuario).filter(models.Usuario.email == dados.email).first()
    if usuario_existente:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Este e-mail já está cadastrado."
        )

    # Cria Perfil do Usuário
    novo_usuario = models.Usuario(
        email=dados.email,
        nome=dados.nome
    )
    db.add(novo_usuario)
    db.flush()

    # Cria Credencial (senha com hash)
    nova_credencial = models.Credencial(
        usuario_id=novo_usuario.id,
        senha_hash=security.hash_password(dados.senha)
    )
    db.add(nova_credencial)

    db.commit()
    db.refresh(novo_usuario)
    return novo_usuario


@app.post("/auth/login", response_model=schemas.TokenResponse, tags=["Autenticação"])
def login(dados: schemas.LoginRequest, db: Session = Depends(get_db)):
    """Valida credenciais, gera token JWT e grava a sessão ativa no banco com proteção a Timing Attacks."""
    usuario = db.query(models.Usuario).filter(models.Usuario.email == dados.email).first()
    if not usuario or not usuario.credencial:
        # Mitigação contra Timing Attack: consome exatamente o mesmo tempo de processamento
        security.verify_dummy_password(dados.senha)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="E-mail ou senha incorretos."
        )

    if not security.verify_password(dados.senha, usuario.credencial.senha_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="E-mail ou senha incorretos."
        )

    usuario.credencial.ultimo_login = datetime.utcnow()

    # Limpeza de sessões expiradas ou revogadas deste usuário (evita crescimento infinito da tabela)
    db.query(models.SessaoAtiva).filter(
        models.SessaoAtiva.usuario_id == usuario.id,
        (models.SessaoAtiva.expira_em < datetime.utcnow()) | (models.SessaoAtiva.revogado == True)
    ).delete(synchronize_session=False)

    # Gera token JWT
    token = security.create_access_token(data={"sub": usuario.id, "email": usuario.email})

    # Registra a sessão na tabela sessoes_ativas
    token_hash = security.hash_token(token)
    expira_em = datetime.utcnow() + timedelta(minutes=security.ACCESS_TOKEN_EXPIRE_MINUTES)
    nova_sessao = models.SessaoAtiva(
        usuario_id=usuario.id,
        refresh_token_hash=token_hash,
        expira_em=expira_em,
        revogado=False
    )
    db.add(nova_sessao)
    db.commit()

    return {
        "access_token": token,
        "token_type": "bearer",
        "usuario": usuario
    }


@app.post("/auth/oauth-sync", response_model=schemas.TokenResponse, tags=["Autenticação"])
def oauth_sync_login(
        dados: schemas.OAuthSyncRequest,
        credentials: HTTPAuthorizationCredentials = Depends(security_scheme),
        db: Session = Depends(get_db)
):
    """
    Sincroniza e autentica usuários que entraram via OAuth (Google / Supabase, usado pelo Ametist).
    A identidade vem do access token do Supabase, verificado aqui com SUPABASE_JWT_SECRET;
    o e-mail do corpo do pedido nunca é confiado. Sem SUPABASE_JWT_SECRET o endpoint fica desligado.
    """
    if not os.getenv("SUPABASE_JWT_SECRET", "").strip():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Login federado não está configurado neste servidor."
        )

    claims = security.verify_supabase_token(credentials.credentials)
    if not claims:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token do provedor inválido ou expirado.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    email = str(claims["email"]).strip().lower()
    meta = claims.get("user_metadata") or {}
    nome = dados.nome or security.sanitize_text(meta.get("full_name") or meta.get("name")) or email.split("@")[0]
    avatar_url = dados.avatar_url or meta.get("avatar_url")

    usuario = db.query(models.Usuario).filter(models.Usuario.email == email).first()
    if not usuario:
        usuario = models.Usuario(email=email, nome=nome, avatar_url=avatar_url)
        db.add(usuario)
        db.flush()

        # Credencial técnica aleatória para contas federadas (sem login por senha)
        db.add(models.Credencial(
            usuario_id=usuario.id,
            senha_hash=security.hash_password(f"oauth_{uuid.uuid4().hex}!Aa1")
        ))
        db.commit()
        db.refresh(usuario)
    elif avatar_url and not usuario.avatar_url:
        usuario.avatar_url = avatar_url
        db.commit()
        db.refresh(usuario)

    token = security.create_access_token(data={"sub": usuario.id, "email": usuario.email})
    db.add(models.SessaoAtiva(
        usuario_id=usuario.id,
        refresh_token_hash=security.hash_token(token),
        expira_em=datetime.utcnow() + timedelta(minutes=security.ACCESS_TOKEN_EXPIRE_MINUTES),
        revogado=False
    ))
    db.commit()

    return {
        "access_token": token,
        "token_type": "bearer",
        "usuario": usuario
    }


@app.post("/auth/logout", response_model=schemas.MensagemResponse, tags=["Autenticação"])
def logout(
        credentials: HTTPAuthorizationCredentials = Depends(security_scheme),
        usuario_atual: models.Usuario = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    """Encerra a sessão atual e revoga o token na tabela sessoes_ativas."""
    token = credentials.credentials
    token_hash = security.hash_token(token)

    sessao = db.query(models.SessaoAtiva).filter(
        models.SessaoAtiva.refresh_token_hash == token_hash,
        models.SessaoAtiva.usuario_id == usuario_atual.id
    ).first()

    if sessao:
        sessao.revogado = True
        db.commit()

    return {"mensagem": "Logout realizado com sucesso. Sessão encerrada."}


@app.put("/auth/alterar-senha", response_model=schemas.MensagemResponse, tags=["Autenticação"])
def alterar_senha(
        dados: schemas.AlterarSenhaRequest,
        usuario_atual: models.Usuario = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    """Permite ao usuário autenticado alterar sua senha."""
    if not security.verify_password(dados.senha_atual, usuario_atual.credencial.senha_hash):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="A senha atual está incorreta."
        )

    usuario_atual.credencial.senha_hash = security.hash_password(dados.nova_senha)

    # Troca de senha invalida todas as sessões existentes (inclusive roubadas)
    db.query(models.SessaoAtiva).filter(
        models.SessaoAtiva.usuario_id == usuario_atual.id
    ).update({"revogado": True}, synchronize_session=False)
    db.commit()
    return {"mensagem": "Senha alterada com sucesso! Faça login novamente."}


@app.post("/auth/recuperar-senha", response_model=schemas.MensagemResponse, tags=["Autenticação"])
def solicitar_recuperacao_senha(email: str, db: Session = Depends(get_db)):
    """Simula a solicitação de recuperação de senha."""
    # Ainda não envia e-mail. Resposta idêntica exista ou não a conta, para não expor cadastros.
    return {"mensagem": "Se o e-mail estiver cadastrado, as instruções de recuperação foram enviadas."}


# ==========================================
# ROTAS DE TICKETS SSO ENTRE ASTRALYS & AMETIST
# ==========================================

@app.post("/auth/sso/ticket", response_model=schemas.SsoTicketResponse, tags=["Autenticação"])
def gerar_sso_ticket(usuario_atual: models.Usuario = Depends(get_current_user)):
    """Gera um ticket efêmero (60 segundos) de uso único para SSO entre Astralys e Ametist."""
    ticket = security.create_sso_ticket(usuario_atual.id, lifetime_seconds=60)
    return {"ticket": ticket, "expires_in": 60}


@app.post("/auth/sso/exchange", response_model=schemas.TokenResponse, tags=["Autenticação"])
def trocar_sso_ticket(dados: schemas.SsoExchangeRequest, db: Session = Depends(get_db)):
    """Troca um ticket SSO efêmero e de uso único por uma sessão autenticada com novo JWT."""
    user_id = security.consume_sso_ticket(dados.ticket)
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Ticket SSO inválido, expirado ou já utilizado."
        )

    usuario = db.query(models.Usuario).filter(models.Usuario.id == user_id).first()
    if not usuario:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Usuário associado ao ticket não encontrado."
        )

    # Gera token JWT novo e seguro para a aplicação solicitante
    token = security.create_access_token(data={"sub": usuario.id, "email": usuario.email})

    # Registra a sessão na tabela sessoes_ativas
    token_hash = security.hash_token(token)
    expira_em = datetime.utcnow() + timedelta(minutes=security.ACCESS_TOKEN_EXPIRE_MINUTES)
    nova_sessao = models.SessaoAtiva(
        usuario_id=usuario.id,
        refresh_token_hash=token_hash,
        expira_em=expira_em,
        revogado=False
    )
    db.add(nova_sessao)
    db.commit()

    return {
        "access_token": token,
        "token_type": "bearer",
        "usuario": usuario
    }



# ==========================================
# ROTAS DO CRUD DE PERFIS (USUÁRIOS)
# ==========================================

# READ (Meu Perfil)
@app.get("/usuarios/me", response_model=schemas.UsuarioResponse, tags=["Perfis"])
def obter_meu_perfil(usuario_atual: models.Usuario = Depends(get_current_user)):
    """Retorna o perfil do usuário logado via Token JWT."""
    return usuario_atual


# UPDATE (Editar Perfil: nome, avatar, status)
@app.put("/usuarios/me", response_model=schemas.UsuarioResponse, tags=["Perfis"])
def atualizar_meu_perfil(
        dados: schemas.UsuarioUpdate,
        usuario_atual: models.Usuario = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    """Atualiza dados do perfil: nome, avatar_url e status_recado."""
    if dados.nome is not None:
        usuario_atual.nome = dados.nome
    if dados.avatar_url is not None:
        usuario_atual.avatar_url = dados.avatar_url
    if dados.status_recado is not None:
        usuario_atual.status_recado = dados.status_recado

    db.commit()
    db.refresh(usuario_atual)
    return usuario_atual


# DELETE (Excluir Conta e Perfil)
@app.delete("/usuarios/me", response_model=schemas.MensagemResponse, tags=["Perfis"])
def excluir_minha_conta(
        usuario_atual: models.Usuario = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    """Exclui a conta e perfil do usuário logado (remove credenciais e sessões em cascata)."""
    db.delete(usuario_atual)
    db.commit()
    return {"mensagem": "Conta e perfil excluídos com sucesso."}


# READ (Listar todos os perfis - para o serviço de chat)
@app.get("/usuarios", response_model=List[schemas.PerfilPublico], tags=["Perfis"])
def listar_usuarios(
        limit: int = Query(50, ge=1, le=100),
        offset: int = Query(0, ge=0),
        usuario_atual: models.Usuario = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    """Lista perfis públicos (sem e-mail), paginado. Exige login."""
    return db.query(models.Usuario).order_by(models.Usuario.nome).offset(offset).limit(limit).all()


# READ (Buscar perfil por ID)
@app.get("/usuarios/{usuario_id}", response_model=schemas.PerfilPublico, tags=["Perfis"])
def obter_usuario_por_id(
        usuario_id: str,
        usuario_atual: models.Usuario = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    """Busca o perfil público (sem e-mail) de um usuário. Exige login."""
    usuario = db.query(models.Usuario).filter(models.Usuario.id == usuario_id).first()
    if not usuario:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Usuário não encontrado."
        )
    return usuario


# ==========================================
# ROTAS DO ASTRALYS (PROJETOS & CÁLCULOS)
# ==========================================

@app.get("/astralys/projetos", response_model=List[schemas.ProjetoCalculoResponse], tags=["Astralys - Projetos & Cálculos"])
def listar_meus_projetos(
    usuario_atual: models.Usuario = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Lista todos os projetos e planilhas de cálculo do usuário logado."""
    return db.query(models.ProjetoCalculo).filter(
        models.ProjetoCalculo.usuario_id == usuario_atual.id
    ).order_by(models.ProjetoCalculo.atualizado_em.desc()).all()


@app.get("/astralys/projetos/publicos", response_model=List[schemas.ProjetoResumo], tags=["Astralys - Projetos & Cálculos"])
def listar_projetos_publicos(
        limit: int = Query(30, ge=1, le=100),
        offset: int = Query(0, ge=0),
        db: Session = Depends(get_db)
):
    """Lista resumos (sem o JSON completo) de projetos públicos, paginado. Use GET /{id} para o conteúdo."""
    return db.query(models.ProjetoCalculo).filter(
        models.ProjetoCalculo.is_public == True
    ).order_by(models.ProjetoCalculo.atualizado_em.desc()).offset(offset).limit(limit).all()


@app.get("/astralys/publicos/{projeto_id}", response_model=schemas.ProjetoPublico, tags=["Astralys - Projetos & Cálculos"])
def obter_projeto_publico(projeto_id: str, db: Session = Depends(get_db)):
    """Lê um projeto marcado como público, SEM login (link de compartilhamento). Privado ou inexistente: 404."""
    projeto = db.query(models.ProjetoCalculo).filter(
        models.ProjetoCalculo.id == projeto_id,
        models.ProjetoCalculo.is_public == True
    ).first()
    if not projeto:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Projeto não encontrado ou não é público.")
    return projeto


@app.get("/astralys/projetos/{projeto_id}", response_model=schemas.ProjetoCalculoResponse, tags=["Astralys - Projetos & Cálculos"])
def obter_projeto(
    projeto_id: str,
    usuario_atual: models.Usuario = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Obtém detalhes e dados completos de um projeto pelo ID."""
    projeto = db.query(models.ProjetoCalculo).filter(
        models.ProjetoCalculo.id == projeto_id
    ).first()

    if not projeto:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Projeto não encontrado."
        )

    # Permitir acesso se for do próprio usuário ou se for público
    if projeto.usuario_id != usuario_atual.id and not projeto.is_public:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Você não tem permissão para acessar este projeto privado."
        )

    return projeto


@app.post("/astralys/projetos", response_model=schemas.ProjetoCalculoResponse, status_code=status.HTTP_201_CREATED, tags=["Astralys - Projetos & Cálculos"])
def salvar_projeto(
    dados: schemas.ProjetoCalculoCreate,
    usuario_atual: models.Usuario = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Cria ou atualiza (upsert) uma planilha de cálculo para o usuário logado."""
    proj_id = dados.id or str(uuid.uuid4())
    projeto_existente = db.query(models.ProjetoCalculo).filter(
        models.ProjetoCalculo.id == proj_id
    ).first()

    if projeto_existente and projeto_existente.usuario_id != usuario_atual.id:
        # Não revela de quem é: o id simplesmente não está disponível
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Este identificador de projeto já está em uso. Gere um novo id."
        )

    if projeto_existente:
        projeto_existente.nome = dados.nome
        projeto_existente.character_name = dados.character_name
        projeto_existente.role = dados.role or "Main DPS"
        projeto_existente.version = dados.version or "1.0"
        projeto_existente.author = usuario_atual.nome
        projeto_existente.dados = dados.dados
        if dados.is_public is not None:
            projeto_existente.is_public = bool(dados.is_public)
        projeto_existente.atualizado_em = datetime.utcnow()
        db.commit()
        db.refresh(projeto_existente)
        return projeto_existente

    novo_projeto = models.ProjetoCalculo(
        id=proj_id,
        usuario_id=usuario_atual.id,
        nome=dados.nome,
        character_name=dados.character_name,
        role=dados.role or "Main DPS",
        version=dados.version or "1.0",
        author=usuario_atual.nome,
        dados=dados.dados,
        is_public=bool(dados.is_public) if dados.is_public is not None else False,
        criado_em=datetime.utcnow(),
        atualizado_em=datetime.utcnow()
    )
    db.add(novo_projeto)
    db.commit()
    db.refresh(novo_projeto)
    return novo_projeto


@app.put("/astralys/projetos/{projeto_id}", response_model=schemas.ProjetoCalculoResponse, tags=["Astralys - Projetos & Cálculos"])
def atualizar_projeto(
    projeto_id: str,
    dados: schemas.ProjetoCalculoUpdate,
    usuario_atual: models.Usuario = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Atualiza dados parciais ou completos de um projeto existente."""
    projeto = db.query(models.ProjetoCalculo).filter(
        models.ProjetoCalculo.id == projeto_id,
        models.ProjetoCalculo.usuario_id == usuario_atual.id
    ).first()

    if not projeto:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Projeto não encontrado ou você não tem permissão para editá-lo."
        )

    if dados.nome is not None:
        projeto.nome = dados.nome
    if dados.character_name is not None:
        projeto.character_name = dados.character_name
    if dados.role is not None:
        projeto.role = dados.role
    if dados.version is not None:
        projeto.version = dados.version
    if dados.dados is not None:
        projeto.dados = dados.dados
    if dados.is_public is not None:
        projeto.is_public = bool(dados.is_public)

    projeto.atualizado_em = datetime.utcnow()
    db.commit()
    db.refresh(projeto)
    return projeto


@app.delete("/astralys/projetos/{projeto_id}", response_model=schemas.MensagemResponse, tags=["Astralys - Projetos & Cálculos"])
def excluir_projeto(
    projeto_id: str,
    usuario_atual: models.Usuario = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Exclui um projeto de cálculo pertencente ao usuário logado."""
    projeto = db.query(models.ProjetoCalculo).filter(
        models.ProjetoCalculo.id == projeto_id,
        models.ProjetoCalculo.usuario_id == usuario_atual.id
    ).first()

    if not projeto:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Projeto não encontrado ou permissão negada."
        )

    db.delete(projeto)
    db.commit()
    return {"mensagem": f"Projeto '{projeto.nome}' excluído com sucesso."}


@app.post("/astralys/projetos/sync", response_model=List[schemas.ProjetoCalculoResponse], tags=["Astralys - Projetos & Cálculos"])
def sincronizar_projetos(
    payload: schemas.ProjetoSyncRequest,
    usuario_atual: models.Usuario = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Sincroniza múltiplos projetos locais (localStorage) com o banco na nuvem."""
    for item in payload.projetos:
        proj_id = item.id or str(uuid.uuid4())
        existente = db.query(models.ProjetoCalculo).filter(
            models.ProjetoCalculo.id == proj_id
        ).first()

        if existente and existente.usuario_id != usuario_atual.id:
            continue  # id pertence a outro usuário: ignora este item em vez de derrubar o lote inteiro

        if existente:
            existente.nome = item.nome
            existente.character_name = item.character_name
            existente.role = item.role or existente.role
            existente.version = item.version or existente.version
            existente.author = usuario_atual.nome
            existente.dados = item.dados
            if item.is_public is not None:
                existente.is_public = bool(item.is_public)
            existente.atualizado_em = datetime.utcnow()
        else:
            novo = models.ProjetoCalculo(
                id=proj_id,
                usuario_id=usuario_atual.id,
                nome=item.nome,
                character_name=item.character_name,
                role=item.role or "Main DPS",
                version=item.version or "1.0",
                author=usuario_atual.nome,
                dados=item.dados,
                is_public=bool(item.is_public) if item.is_public is not None else False,
                criado_em=datetime.utcnow(),
                atualizado_em=datetime.utcnow()
            )
            db.add(novo)
    db.commit()

    return db.query(models.ProjetoCalculo).filter(
        models.ProjetoCalculo.usuario_id == usuario_atual.id
    ).order_by(models.ProjetoCalculo.atualizado_em.desc()).all()
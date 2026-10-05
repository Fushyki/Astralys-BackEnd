-- ==========================================================
-- SCRIPT DDL - MICROSSERVIÇO DE IDENTIDADE E PERFIS (MYSQL)
-- ==========================================================

-- 1. Criação do Banco de Dados
CREATE DATABASE IF NOT EXISTS usuario
CHARACTER SET utf8mb4
COLLATE utf8mb4_unicode_ci;

USE usuario;

-- 2. Tabela de Usuários (Perfil Público)
CREATE TABLE IF NOT EXISTS usuarios (
    id VARCHAR(36) PRIMARY KEY,
    email VARCHAR(255) NOT NULL UNIQUE,
    nome VARCHAR(255) NOT NULL,
    avatar_url VARCHAR(500) NULL,
    status_recado VARCHAR(255) DEFAULT 'Olá! Estou usando o chat.',
    criado_em DATETIME DEFAULT CURRENT_TIMESTAMP,
    atualizado_em DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 3. Tabela de Credenciais (Segurança e Hash de Senha)
CREATE TABLE IF NOT EXISTS credenciais (
    id VARCHAR(36) PRIMARY KEY,
    usuario_id VARCHAR(36) NOT NULL UNIQUE,
    senha_hash VARCHAR(255) NOT NULL,
    ultimo_login DATETIME NULL,
    CONSTRAINT fk_credenciais_usuario
        FOREIGN KEY (usuario_id) REFERENCES usuarios (id)
        ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 4. Tabela de Sessões Ativas (Controle de Tokens e Sessões)
CREATE TABLE IF NOT EXISTS sessoes_ativas (
    id VARCHAR(36) PRIMARY KEY,
    usuario_id VARCHAR(36) NOT NULL,
    refresh_token_hash VARCHAR(255) NOT NULL,
    expira_em DATETIME NOT NULL,
    revogado BOOLEAN DEFAULT FALSE,
    CONSTRAINT fk_sessoes_usuario
        FOREIGN KEY (usuario_id) REFERENCES usuarios (id)
        ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 5. Tabela de Planilhas e Projetos do Astralys
CREATE TABLE IF NOT EXISTS astralys_projetos (
    id VARCHAR(36) PRIMARY KEY,
    usuario_id VARCHAR(36) NOT NULL,
    nome VARCHAR(255) NOT NULL,
    character_name VARCHAR(100) NOT NULL,
    role VARCHAR(50) DEFAULT 'Main DPS',
    version VARCHAR(20) DEFAULT '1.0',
    author VARCHAR(100) DEFAULT 'Astralys',
    dados JSON NOT NULL,
    is_public BOOLEAN DEFAULT FALSE,
    criado_em DATETIME DEFAULT CURRENT_TIMESTAMP,
    atualizado_em DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    CONSTRAINT fk_astralys_projetos_usuario
        FOREIGN KEY (usuario_id) REFERENCES usuarios (id)
        ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;


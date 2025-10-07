from datetime import datetime, timedelta, timezone

import jwt
import psycopg2
from flask import Blueprint, current_app, jsonify, request
from flask_bcrypt import Bcrypt

from auth import token_obrigatorio  # Importando o decorador de autenticação

# Importações de outros módulos
from banco import get_db_connection

# 1. Instância do Bcrypt
# Criamos a instância do Bcrypt aqui, mas a inicialização com o app principal
# (bcrypt.init_app(app)) ocorrerá em app.py para evitar dependências circulares.
bcrypt = Bcrypt()

# 2. Definição do Blueprint
gestor_bp = Blueprint('gestor', __name__)


# 5. Rota: Criar um novo Gestor (Cadastro)
@gestor_bp.route('/gestor', methods=['POST'])
def criar_gestor():
    """Cria um novo gestor, gerando o hash da senha."""
    data = request.get_json()
    nome = data.get('nome')
    email = data.get('email')
    senha_plana = data.get('senha')

    if not all([nome, email, senha_plana]):
        return jsonify({"error": "Nome, email e senha são obrigatórios."}), 400

    # Cria o hash seguro da senha
    senha_hash_seguro = bcrypt.generate_password_hash(senha_plana).decode(
        'utf-8')

    conn = get_db_connection()
    if conn is None:
        return jsonify({"error": "Falha na conexão com o banco de dados"}), 500

    try:
        cur = conn.cursor()
        query = """
            INSERT INTO gestores (nome, email, senha_hash) 
            VALUES (%s, %s, %s) 
            RETURNING gestor_id;
        """
        cur.execute(query, (nome, email, senha_hash_seguro))

        resultado = cur.fetchone()

        if resultado is None:
            raise Exception("Falha na inserção, ID não retornado pelo DB.")

        gestor_id = resultado[0]

        conn.commit()
        cur.close()

        return jsonify({
            "message": "Gestor criado com sucesso",
            "gestor_id": gestor_id
        }), 201

    except psycopg2.errors.UniqueViolation:
        conn.rollback()
        return jsonify({"error": "Email já cadastrado."}), 409
    except Exception as e:
        conn.rollback()
        print(f"Erro ao criar gestor: {e}")
        return jsonify(
            {"error": f"Erro interno ao criar gestor. Detalhe: {e}"}), 500

    finally:
        if conn:
            conn.close()


# 6. Rota: Login do Gestor (Verificação de Senha e Geração de JWT)
@gestor_bp.route('/login/gestor', methods=['POST'])
def login_gestor():
    """Verifica credenciais e gera um token JWT para o gestor."""
    data = request.get_json()
    email = data.get('email')
    senha_plana = data.get('senha')

    if not all([email, senha_plana]):
        return jsonify({"error": "Email e senha são obrigatórios."}), 400

    conn = get_db_connection()
    if conn is None:
        return jsonify({"error": "Falha na conexão com o banco de dados"}), 500

    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT gestor_id, nome, senha_hash FROM gestores WHERE email = %s;",
            (email, ))
        gestor_data = cur.fetchone()
        cur.close()

        if gestor_data is None:
            return jsonify({"error": "Credenciais inválidas."}), 401

        gestor_id, nome_gestor, senha_hash_do_db = gestor_data

        # 1. Verifica a senha com o hash
        if bcrypt.check_password_hash(senha_hash_do_db, senha_plana):

            # 2. GERAÇÃO DO JWT
            expiracao = datetime.now(timezone.utc) + timedelta(hours=24)

            payload = {
                'gestor_id': gestor_id,
                'nome': nome_gestor,
                'exp': expiracao,  # Expiração
                'iat': datetime.now(timezone.utc),  # Emitido em
                'role': 'gestor'  # Define a função do usuário
            }

            # Codifica usando a chave SESSION_SECRET do app principal
            token = jwt.encode(payload,
                               current_app.config['SESSION_SECRET'],
                               algorithm='HS256')

            return jsonify({
                "message": "Login bem-sucedido!",
                "gestor_id": gestor_id,
                "token": token
            }), 200
        else:
            return jsonify({"error": "Credenciais inválidas."}), 401

    except Exception as e:
        print(f"Erro durante o login: {e}")
        return jsonify({"error": "Erro interno do servidor."}), 500

    finally:
        if conn:
            conn.close()


# 7. Rota: Meu Perfil do Gestor (Protegida)
@gestor_bp.route('/gestor/meu-perfil', methods=['GET'])
@token_obrigatorio('gestor') # Proteção de rota garantindo a role 'gestor'
def meu_perfil_gestor(dados_usuario):
    """
    Retorna os dados básicos do perfil do gestor logado,
    usando o gestor_id extraído do token JWT.
    """
    # O decorador garante que o token é válido e a role é 'gestor'.
    gestor_id_do_token = dados_usuario.get('gestor_id')

    conn = get_db_connection()
    if conn is None:
        return jsonify({"error": "Falha na conexão com o banco de dados"}), 500

    try:
        cur = conn.cursor()

        # Seleciona apenas dados que não são sensíveis
        cur.execute(
            "SELECT gestor_id, nome, email, data_cadastro FROM gestores WHERE gestor_id = %s;",
            (gestor_id_do_token, )
        )
        gestor_perfil = cur.fetchone()
        cur.close()

        if gestor_perfil is None:
            # Isso só deve acontecer se o ID do token for válido mas o gestor foi deletado
            return jsonify({"error": "Gestor não encontrado."}), 404

        # Mapeia o resultado da tupla para um dicionário
        perfil = {
            "gestor_id": gestor_perfil[0],
            "nome": gestor_perfil[1],
            "email": gestor_perfil[2],
            "data_cadastro": gestor_perfil[3].isoformat() if gestor_perfil[3] else None
        }

        return jsonify(perfil), 200

    except Exception as e:
        print(f"Erro ao buscar perfil do gestor: {e}")
        return jsonify({"error": "Erro interno ao buscar perfil."}), 500

    finally:
        if conn:
            conn.close()

from datetime import datetime, timedelta, timezone

import jwt
import psycopg2
from flask import Blueprint, current_app, jsonify, request

from auth import token_obrigatorio  # <--- Importação necessária do decorador

# Importações de outros módulos
from banco import get_db_connection

# O Bcrypt é usado aqui, importado da instância inicializada em gestor.py
from gestor import bcrypt

# Definição do Blueprint
cliente_bp = Blueprint('cliente', __name__)


# 8. Rota: Criar um novo Cliente (Cadastro)
@cliente_bp.route('/cliente', methods=['POST'])
def criar_cliente():
    """Cria um novo cliente, gerando o hash da senha."""
    data = request.get_json()
    nome = data.get('nome')
    email = data.get('email')
    senha_plana = data.get('senha')

    if not all([nome, email, senha_plana]):
        return jsonify({"error": "Nome, email e senha são obrigatórios."}), 400

    # Cria o hash seguro da senha, usando a instância global do Bcrypt
    senha_hash_seguro = bcrypt.generate_password_hash(senha_plana).decode(
        'utf-8')

    conn = get_db_connection()
    if conn is None:
        return jsonify({"error": "Falha na conexão com o banco de dados"}), 500

    try:
        cur = conn.cursor()
        query = """
            INSERT INTO clientes (nome, email, senha_hash) 
            VALUES (%s, %s, %s) 
            RETURNING cliente_id;
        """
        cur.execute(query, (nome, email, senha_hash_seguro))

        resultado = cur.fetchone()

        if resultado is None:
            raise Exception(
                "Falha na inserção, ID do cliente não retornado pelo DB.")

        cliente_id = resultado[0]

        conn.commit()
        cur.close()

        return jsonify({
            "message": "Cliente criado com sucesso",
            "cliente_id": cliente_id
        }), 201

    except psycopg2.errors.UniqueViolation:
        conn.rollback()
        return jsonify({"error": "Email de cliente já cadastrado."}), 409
    except Exception as e:
        conn.rollback()
        print(f"Erro ao criar cliente: {e}")
        return jsonify(
            {"error": f"Erro interno ao criar cliente. Detalhe: {e}"}), 500

    finally:
        if conn:
            conn.close()


# 9. Rota: Login do Cliente (Verificação de Senha e Geração de JWT)
@cliente_bp.route('/login/cliente', methods=['POST'])
def login_cliente():
    """Verifica credenciais e gera um token JWT para o cliente."""
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
            "SELECT cliente_id, nome, senha_hash FROM clientes WHERE email = %s;",
            (email, ))
        cliente_data = cur.fetchone()
        cur.close()

        if cliente_data is None:
            return jsonify({"error": "Credenciais inválidas."}), 401

        cliente_id, nome_cliente, senha_hash_do_db = cliente_data

        # 1. Verifica a senha com o hash
        if bcrypt.check_password_hash(senha_hash_do_db, senha_plana):

            # 2. GERAÇÃO DO JWT
            expiracao = datetime.now(timezone.utc) + timedelta(hours=24)

            # Usamos 'current_app' para acessar a configuração SESSION_SECRET
            session_secret = current_app.config.get('SESSION_SECRET')

            if not session_secret:
                return jsonify(
                    {'message': 'Erro de configuração do servidor.'}), 500

            payload = {
                'cliente_id': cliente_id,
                'nome': nome_cliente,
                'exp': expiracao,  # Expiração
                'iat': datetime.now(timezone.utc),  # Emitido em
                'role': 'cliente'  # Define a função do usuário como 'cliente'
            }

            # Codifica usando a chave SESSION_SECRET
            token = jwt.encode(payload, session_secret, algorithm='HS256')

            return jsonify({
                "message": "Login de cliente bem-sucedido!",
                "cliente_id": cliente_id,
                "token": token
            }), 200
        else:
            return jsonify({"error": "Credenciais inválidas."}), 401

    except Exception as e:
        print(f"Erro durante o login do cliente: {e}")
        return jsonify({"error": "Erro interno do servidor."}), 500

    finally:
        if conn:
            conn.close()


## Rota 10. Meu Perfil (Protegida)


# 10. Rota: Meu Perfil (Dados do Cliente Logado)
@cliente_bp.route('/cliente/meu-perfil', methods=['GET'])
@token_obrigatorio(
    'cliente')  # <--- AGORA ESTÁ CORRETO: Protegido APENAS para 'cliente'
def meu_perfil(dados_usuario
               ):  # Renomeado para 'dados_usuario' para ser mais genérico
    """
    Retorna os dados básicos do perfil do cliente logado,
    usando o cliente_id extraído do token JWT.
    """
    # O decorador garante que o token é válido e a role é 'cliente'.
    cliente_id_do_token = dados_usuario.get('cliente_id')

    conn = get_db_connection()
    if conn is None:
        return jsonify({"error": "Falha na conexão com o banco de dados"}), 500

    try:
        cur = conn.cursor()

        # Seleciona apenas dados que não são sensíveis
        cur.execute(
            "SELECT cliente_id, nome, email, data_cadastro FROM clientes WHERE cliente_id = %s;",
            (cliente_id_do_token, ))
        cliente_perfil = cur.fetchone()
        cur.close()

        if cliente_perfil is None:
            return jsonify({"error": "Cliente não encontrado."}), 404

        # Mapeia o resultado da tupla para um dicionário
        perfil = {
            "cliente_id":
            cliente_perfil[0],
            "nome":
            cliente_perfil[1],
            "email":
            cliente_perfil[2],
            "data_cadastro":
            cliente_perfil[3].isoformat() if cliente_perfil[3] else None
        }

        return jsonify(perfil), 200

    except Exception as e:
        print(f"Erro ao buscar perfil do cliente: {e}")
        return jsonify({"error": "Erro interno ao buscar perfil."}), 500

    finally:
        if conn:
            conn.close()
            # Continuação de cliente.py
            # Nota: O GET para 'meu-perfil' já existe, o PUT e DELETE devem usar a mesma rota.

            # 11. Rota Protegida: Atualizar Meu Perfil de Cliente
            @cliente_bp.route('/cliente/meu-perfil', methods=['PUT'])
            @token_obrigatorio('cliente')
            def atualizar_cliente(dados_usuario):
                """Permite ao cliente logado atualizar seu nome ou senha."""
                cliente_id = dados_usuario.get('cliente_id')
                data = request.get_json()

                # Campos que podem ser atualizados
                nome = data.get('nome')
                senha_plana = data.get('senha')

                updates = []
                valores = []

                if nome:
                    updates.append("nome = %s")
                    valores.append(nome)

                if senha_plana:
                    # Gera o hash seguro da nova senha
                    senha_hash_seguro = bcrypt.generate_password_hash(
                        senha_plana).decode('utf-8')
                    updates.append("senha_hash = %s")
                    valores.append(senha_hash_seguro)

                if not updates:
                    return jsonify({
                        "error":
                        "Nenhum dado (nome ou senha) fornecido para atualização."
                    }), 400

                conn = get_db_connection()
                if conn is None:
                    return jsonify(
                        {"error":
                         "Falha na conexão com o banco de dados"}), 500

                try:
                    cur = conn.cursor()

                    query = f"""
                        UPDATE clientes 
                        SET {', '.join(updates)}
                        WHERE cliente_id = %s
                        RETURNING cliente_id;
                    """
                    # Adiciona o ID do cliente para o filtro WHERE
                    valores.append(cliente_id)

                    cur.execute(query, tuple(valores))

                    if cur.rowcount == 0:
                        conn.rollback()
                        return jsonify({
                            "error":
                            "Cliente não encontrado para atualização."
                        }), 404

                    conn.commit()
                    cur.close()

                    return jsonify({
                        "message":
                        "Perfil de cliente atualizado com sucesso."
                    }), 200

                except Exception as e:
                    conn.rollback()
                    print(f"Erro ao atualizar cliente: {e}")
                    return jsonify({
                        "error":
                        f"Erro interno ao atualizar perfil. Detalhe: {e}"
                    }), 500

                finally:
                    if conn:
                        conn.close()

            # 12. Rota Protegida: Deletar Meu Perfil de Cliente
            @cliente_bp.route('/cliente/meu-perfil', methods=['DELETE'])
            @token_obrigatorio('cliente')
            def deletar_cliente(dados_usuario):
                """Permite ao cliente logado deletar sua própria conta."""
                cliente_id = dados_usuario.get('cliente_id')

                conn = get_db_connection()
                if conn is None:
                    return jsonify(
                        {"error":
                         "Falha na conexão com o banco de dados"}), 500

                try:
                    cur = conn.cursor()

                    # Deletar o cliente
                    query = "DELETE FROM clientes WHERE cliente_id = %s;"
                    cur.execute(query, (cliente_id, ))

                    if cur.rowcount == 0:
                        conn.rollback()
                        return jsonify(
                            {"error":
                             "Cliente não encontrado para deleção."}), 404

                    conn.commit()
                    cur.close()

                    return jsonify(
                        {"message":
                         "Conta de cliente deletada com sucesso."}), 200

                except Exception as e:
                    conn.rollback()
                    print(f"Erro ao deletar cliente: {e}")
                    # Se houver pedidos ou outros dados associados
                    if "foreign key constraint" in str(e).lower():
                        return jsonify({
                            "error":
                            "Não é possível deletar a conta: Existem pedidos ou outros dados associados."
                        }), 409

                    return jsonify({
                        "error":
                        f"Erro interno ao deletar cliente. Detalhe: {e}"
                    }), 500

                finally:
                    if conn:
                        conn.close()

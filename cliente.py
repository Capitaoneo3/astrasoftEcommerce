import os
from datetime import datetime, timedelta, timezone
from io import BytesIO  # Importação necessária para send_file

import jwt
import psycopg2
import psycopg2.errors
from flask import Blueprint, current_app, jsonify, request, send_file

from auth import token_obrigatorio  # <--- Importação necessária do decorador
from banco import get_db_connection

# Importações de outros módulos
# O Bcrypt é usado aqui, importado da instância inicializada em gestor.py
from gestor import bcrypt, client

# Definição do Blueprint
cliente_bp = Blueprint('cliente', __name__)


# 8. Rota: Criar um novo Cliente (Cadastro) - COM JWT
@cliente_bp.route('/cliente', methods=['POST'])
def criar_cliente():

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

        # 1. GERAÇÃO DO JWT após cadastro bem-sucedido
        expiracao = datetime.now(timezone.utc) + timedelta(hours=24)

        payload = {
            'cliente_id': cliente_id,  # Chave primária do cliente
            'nome': nome,
            'exp': expiracao,  # Expiração (24 horas)
            'iat': datetime.now(timezone.utc),  # Emitido em
            'role': 'cliente'  # Define a função do usuário como 'cliente'
        }

        token = jwt.encode(payload,
                           current_app.config['SESSION_SECRET'],
                           algorithm='HS256')
        # FIM GERAÇÃO JWT

        conn.commit()
        cur.close()

        return jsonify({
            "message": "Cliente criado com sucesso",
            "cliente_id": cliente_id,
            "token": token  # Retornando o token JWT
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


# 10. Rota: Meu Perfil (Dados do Cliente Logado)
@cliente_bp.route('/cliente/meu-perfil', methods=['GET'])
@token_obrigatorio('cliente')
def meu_perfil(dados_usuario):
    """
    GET /cliente/meu-perfil
    Busca os dados do cliente logado no DB e gera um NOVO token JWT (refresh).
    Requer: Token JWT válido e com role 'cliente'.
    Retorna: Dados do perfil e o token JWT atualizado (200).
    """
    # É necessário que as seguintes bibliotecas estejam importadas:
    # from flask import jsonify, current_app
    # from datetime import datetime, timedelta, timezone
    # import jwt

    cliente_id = dados_usuario.get('cliente_id')

    conn = get_db_connection()
    if conn is None:
        return jsonify({"error": "Falha na conexão com o banco de dados"}), 500

    try:
        cur = conn.cursor()

        # Seleciona dados do perfil
        cur.execute(
            "SELECT cliente_id, nome, email, data_cadastro FROM clientes WHERE cliente_id = %s;",
            (cliente_id, ))
        cliente_perfil = cur.fetchone()
        cur.close()

        if cliente_perfil is None:
            return jsonify({"error": "Cliente não encontrado."}), 404

        # Mapeia o resultado da tupla para variáveis e dicionário de perfil
        c_id, nome, email, data_cadastro = cliente_perfil

        perfil = {
            "cliente_id": c_id,
            "nome": nome,
            "email": email,
            "data_cadastro":
            data_cadastro.isoformat() if data_cadastro else None
        }

        # 1. REFRESH/GERAÇÃO DE NOVO TOKEN
        expiracao = datetime.now(timezone.utc) + timedelta(
            hours=24)  # Nova expiração

        payload = {
            'cliente_id': c_id,
            'nome': nome,
            'exp': expiracao,
            'iat': datetime.now(timezone.utc),
            'role': 'cliente'  # Garante que a role é mantida
        }

        token = jwt.encode(payload,
                           current_app.config['SESSION_SECRET'],
                           algorithm='HS256')
        # FIM REFRESH

        # Adiciona o novo token ao dicionário de resposta
        perfil['token'] = token

        return jsonify(perfil), 200

    except Exception as e:
        print(f"Erro ao buscar perfil do cliente: {e}")
        return jsonify({"error": "Erro interno ao buscar perfil."}), 500

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
        return jsonify({"error": "Falha na conexão com o banco de dados"}), 500

    try:
        cur = conn.cursor()

        # Deletar o cliente
        query = "DELETE FROM clientes WHERE cliente_id = %s;"
        cur.execute(query, (cliente_id, ))

        if cur.rowcount == 0:
            conn.rollback()
            return jsonify({"error":
                            "Cliente não encontrado para deleção."}), 404

        conn.commit()
        cur.close()

        return jsonify({"message":
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

        return jsonify(
            {"error": f"Erro interno ao deletar cliente. Detalhe: {e}"}), 500

    finally:
        if conn:
            conn.close()


@cliente_bp.route('/cliente/meu-perfil', methods=['PUT'])  #
@token_obrigatorio('cliente')
def atualizar_cliente(dados_usuario):

    cliente_id = dados_usuario.get('cliente_id')

    # IMPORTANTE: Capturando dados de FORMULÁRIO (multipart/form-data), não JSON.
    nome = request.form.get('nome')
    email = request.form.get('email')
    senha_plana = request.form.get('senha')
    foto = request.files.get('foto_perfil')  # Captura o arquivo

    updates = []
    valores = []

    if nome:
        updates.append("nome = %s")
        valores.append(nome)

    if email:
        updates.append("email = %s")
        valores.append(email)

    if senha_plana:
        # Gera o hash seguro da nova senha (Requer 'bcrypt' disponível)
        senha_hash_seguro = bcrypt.generate_password_hash(senha_plana).decode(
            'utf-8')
        updates.append("senha_hash = %s")
        valores.append(senha_hash_seguro)

    # Verificação preliminar antes de abrir a conexão
    if not updates and not foto:
        return jsonify({
            "error":
            "Nenhum dado (nome, email, senha ou foto) fornecido para atualização."
        }), 400

    conn = get_db_connection()
    if conn is None:
        return jsonify({"error": "Falha na conexão com o banco de dados"}), 500

    try:
        cur = conn.cursor()

        # --- Lógica de Upload de Foto ---
        if foto:
            # 1. Buscar foto antiga do cliente para deletar
            cur.execute(
                "SELECT foto_perfil FROM clientes WHERE cliente_id = %s;",
                (cliente_id, ))
            resultado = cur.fetchone()
            foto_antiga = resultado[0] if resultado and resultado[0] else None

            # 2. Deletar foto antiga do storage se existir
            if foto_antiga:
                # ASSUME que 'client' (Storage Client) está importado/disponível
                try:
                    # 'client.delete' deve ser a função do seu Object Storage
                    client.delete(foto_antiga, ignore_not_found=True)
                except Exception as e:
                    print(
                        f"Aviso: Erro ao deletar foto antiga, mas a atualização continua: {e}"
                    )

            # 3. Fazer upload da nova foto
            extensao = os.path.splitext(
                foto.filename)[1] if foto.filename else '.jpg'
            # Cria um nome de arquivo único e fácil de rastrear
            nome_arquivo = f"cliente_{cliente_id}_perfil{extensao}"

            # Upload do arquivo para o storage
            client.upload_from_bytes(nome_arquivo, foto.read())

            # 4. Adicionar o caminho da nova foto aos updates do DB
            updates.append("foto_perfil = %s")
            valores.append(nome_arquivo)

        # --- Execução do SQL UPDATE ---
        query = f"""
            UPDATE clientes 
            SET {', '.join(updates)}
            WHERE cliente_id = %s;
        """
        # Adiciona o ID do cliente para o filtro WHERE
        valores.append(cliente_id)

        cur.execute(query, tuple(valores))

        if cur.rowcount == 0:
            conn.rollback()
            cur.close()
            return jsonify(
                {"error": "Cliente não encontrado para atualização."}), 404

        conn.commit()
        cur.close()

        return jsonify(
            {"message": "Perfil de cliente atualizado com sucesso."}), 200


    except Exception as e:
        conn.rollback()
        print(f"Erro ao atualizar cliente: {e}")
        return jsonify(
            {"error": f"Erro interno ao atualizar perfil. Detalhe: {e}"}), 500

    finally:
        if conn:
            conn.close()


# 13. Rota: Servir Foto de Perfil do Cliente
@cliente_bp.route("/foto/<int:cliente_id>", methods=["GET"])
def obter_foto_cliente(cliente_id):

    conn = get_db_connection()
    if conn is None:
        return jsonify({"error": "Falha na conexão com o banco de dados"}), 500

    try:
        cur = conn.cursor()
        # MUDANÇA 1: Busca na tabela 'clientes' pelo 'cliente_id'
        cur.execute("SELECT foto_perfil FROM clientes WHERE cliente_id = %s;",
                    (cliente_id, ))
        resultado = cur.fetchone()
        cur.close()

        if not resultado or not resultado[0]:
            return jsonify({"error": "Foto do cliente não encontrada"}), 404

        foto_nome = resultado[0]

        # Baixar foto do storage (Requer 'client' do replit.object_storage ou similar)
        try:
            foto_bytes = client.download_as_bytes(foto_nome)
        except Exception as e:
            print(f"Erro ao baixar foto do cliente do storage: {e}")
            return jsonify(
                {"error": "Arquivo de foto não encontrado no storage"}), 404

        # Determinar o tipo MIME baseado na extensão (Lógica idêntica ao gestor)
        extensao = os.path.splitext(foto_nome)[1].lower()
        mime_types = {
            ".jpg": "image/jpeg",
            ".jpeg": "image/jpeg",
            ".png": "image/png",
            ".gif": "image/gif",
            ".webp": "image/webp"
        }
        mime_type = mime_types.get(extensao, "image/jpeg")

        # Retornar o arquivo de bytes (Requer 'send_file' do Flask e 'BytesIO')
        return send_file(BytesIO(foto_bytes),
                         mimetype=mime_type,
                         as_attachment=False)

    except Exception as e:
        print(f"Erro ao obter foto do cliente: {e}")
        return jsonify(
            {"error":
             "Erro interno ao carregar foto do         cliente."}), 500

    finally:
        if conn:
            conn.close()

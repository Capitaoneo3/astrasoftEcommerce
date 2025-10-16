import os
from datetime import datetime, timedelta, timezone
from io import BytesIO  # Importação necessária para send_file

import jwt  # Importação do JWT
import psycopg2
from flask import Blueprint, current_app, jsonify, request, send_file
from flask_bcrypt import Bcrypt
from replit.object_storage import Client

from auth import token_obrigatorio  # Importando o decorador de autenticação
from banco import get_db_connection

# 1. Instância do Bcrypt
bcrypt = Bcrypt()
client = Client()

# 2. Definição do Blueprint
gestor_bp = Blueprint('gestor', __name__)


# 5. Rota: Criar um novo Gestor (Cadastro)
@gestor_bp.route('/gestor', methods=['POST'])
def criar_gestor():
    """
    POST /gestor
    Cria um novo gestor no banco de dados e gera um token JWT.
    Requer: JSON com 'nome', 'email' e 'senha'.
    Retorna: O ID do gestor criado e o token JWT ou um erro (400, 409, 500).
    """
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

        # 1. GERAÇÃO DO JWT após cadastro bem-sucedido
        expiracao = datetime.now(timezone.utc) + timedelta(hours=24)

        payload = {
            'gestor_id': gestor_id,
            'nome': nome, 
            'exp': expiracao,  # Expiração
            'iat': datetime.now(timezone.utc),  # Emitido em
            'role': 'gestor'  # Define a função do usuário
        }

        token = jwt.encode(payload,
                           current_app.config['SESSION_SECRET'],
                           algorithm='HS256')
        # FIM GERAÇÃO JWT

        conn.commit()
        cur.close()

        return jsonify({
            "message": "Gestor criado com sucesso",
            "gestor_id": gestor_id,
            "token": token # Retornando o token
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
    """
    POST /login/gestor
    Verifica as credenciais do gestor e, se válidas, gera um token JWT.
    Requer: JSON com 'email' e 'senha'.
    Retorna: O 'gestor_id' e o 'token' JWT ou um erro (400, 401, 500).
    """
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
@token_obrigatorio('gestor')
def obter_perfil_gestor(dados_usuario):
    """
    GET /gestor/meu-perfil
    Rota protegida. Retorna os dados do perfil do gestor logado e um token JWT atualizado.
    Requer: Token JWT válido no cabeçalho Authorization.
    Retorna: JSON com 'gestor_id', 'nome', 'email', 'foto_perfil' e 'token' (novo/refresh) ou erro (404, 500).
    """
    gestor_id = dados_usuario.get('gestor_id')

    conn = get_db_connection()
    if conn is None:
        return jsonify({"error": "Falha na conexão com o banco de dados"}), 500

    try:
        cur = conn.cursor()
        # Selecionamos apenas os campos necessários, EXCLUINDO senha_hash por segurança
        cur.execute(
            "SELECT nome, email, foto_perfil FROM gestores WHERE gestor_id = %s;",
            (gestor_id, )
        )
        gestor_data = cur.fetchone()
        cur.close()

        if gestor_data is None:
            return jsonify({"error": "Gestor não encontrado."}), 404

        nome, email, foto_perfil = gestor_data

        # 1. REFRESH/GERAÇÃO DE NOVO TOKEN
        # Criamos um novo token com base nos dados do usuário e do DB (nome atualizado)
        expiracao = datetime.now(timezone.utc) + timedelta(hours=24) # Nova expiração

        payload = {
            'gestor_id': gestor_id,
            'nome': nome, # Usar o nome mais atualizado do DB
            'exp': expiracao,
            'iat': datetime.now(timezone.utc),
            'role': 'gestor'
        }

        token = jwt.encode(payload,
                           current_app.config['SESSION_SECRET'],
                           algorithm='HS256')
        # FIM REFRESH

        return jsonify({
            "gestor_id": gestor_id,
            "nome": nome,
            "email": email,
            # Retorna o nome do arquivo, que pode ser usado para a rota /gestor/foto/<id>
            "foto_perfil": foto_perfil,
            "token": token # Adicionando o token atualizado
        }), 200

    except Exception as e:
        print(f"Erro ao obter perfil do gestor: {e}")
        return jsonify({"error": "Erro interno ao obter perfil."}), 500

    finally:
        if conn:
            conn.close()


# 8. Rota Protegida: Atualizar Meu Perfil de Gestor
@gestor_bp.route('/gestor/meu-perfil', methods=['PUT'])
@token_obrigatorio('gestor')
def atualizar_gestor(dados_usuario):
    """
    PUT /gestor/meu-perfil
    Rota protegida. Permite ao gestor logado atualizar seu nome, senha ou foto de perfil.
    Requer: Token JWT válido e dados de formulário ('nome', 'senha' ou 'foto_perfil').
    Retorna: Mensagem de sucesso ou erro (400, 404, 500).
    """
    # Nota: Assumindo que você tem 'request' e 'bcrypt' importados (Flask e Flask-Bcrypt)
    # e 'client' e 'os' (Storage client e funções de caminho)

    gestor_id = dados_usuario.get('gestor_id')

    # Campos que podem ser atualizados
    nome = request.form.get('nome')
    senha_plana = request.form.get('senha')
    foto = request.files.get('foto_perfil')

    updates = []
    valores = []

    if nome:
        updates.append("nome = %s")
        valores.append(nome)

    if senha_plana:
        # Gera o hash seguro da nova senha (Melhor Prática!)
        senha_hash_seguro = bcrypt.generate_password_hash(senha_plana).decode('utf-8')
        updates.append("senha_hash = %s")
        valores.append(senha_hash_seguro)

    conn = get_db_connection()
    if conn is None:
        return jsonify({"error": "Falha na conexão com o banco de dados"}), 500

    try:
        # USA 'with conn:' e 'with conn.cursor() as cur:' para garantir fechamento
        with conn:
            with conn.cursor() as cur:

                # --- Lógica de Upload de Foto ---
                if foto:
                    # 1. Buscar foto antiga do gestor para deletar
                    cur.execute(
                        "SELECT foto_perfil FROM gestores WHERE gestor_id = %s;",
                        (gestor_id,)
                    )
                    resultado = cur.fetchone()
                    foto_antiga = resultado[0] if resultado and resultado[0] else None

                    # 2. Deletar foto antiga do storage se existir
                    if foto_antiga:
                        try:
                            # A função 'client.delete' deve ser robusta para lidar com falhas
                            client.delete(foto_antiga, ignore_not_found=True)
                        except Exception as e:
                            # Isso é um aviso. Não deve bloquear a atualização de outros campos.
                            print(f"Aviso: Erro ao deletar foto antiga, mas a atualização continua: {e}")

                    # 3. Fazer upload da nova foto
                    extensao = os.path.splitext(foto.filename)[1] if foto.filename else '.jpg'
                    nome_arquivo = f"gestor_{gestor_id}_perfil{extensao}"

                    # Upload do arquivo para o storage
                    # É crucial que este passo seja atômico ou que a falha leve a um rollback
                    client.upload_from_bytes(nome_arquivo, foto.read())

                    # 4. Adicionar o caminho da nova foto aos updates do DB
                    updates.append("foto_perfil = %s")
                    valores.append(nome_arquivo)

                # --- Verificação de Updates ---
                if not updates:
                    return jsonify({
                        "error":
                        "Nenhum dado (nome, senha ou foto) fornecido para atualização."
                    }), 400

                # --- Execução do SQL UPDATE ---
                # Removemos o RETURNING gestor_id, pois não é usado
                query = f"""
                    UPDATE gestores 
                    SET {', '.join(updates)}
                    WHERE gestor_id = %s;
                """
                # Adiciona o ID do gestor para o filtro WHERE
                valores.append(gestor_id)

                cur.execute(query, tuple(valores))

                if cur.rowcount == 0:
                    # O rollback é feito automaticamente pelo 'with conn:', mas o erro 404 é importante
                    # Para drivers que não fazem rollback no 'with', precisamos de conn.rollback() aqui.
                    conn.rollback() 
                    return jsonify(
                        {"error": "Gestor não encontrado para atualização."}), 404

                # O commit é crucial, feito dentro do 'with conn:'
                conn.commit()

        # Resposta de Sucesso
        return jsonify({"message":
                        "Perfil de gestor atualizado com sucesso."}), 200

    except Exception as e:
        # Se ocorrer qualquer erro, faz o rollback e loga o erro
        conn.rollback() 
        print(f"Erro ao atualizar gestor: {e}")
        # Retornar o detalhe 'e' no ambiente de produção pode ser um risco de segurança.
        return jsonify(
            {"error": "Erro interno ao atualizar perfil."}), 500

    finally:
        if conn:
            # O 'with conn' deveria fechar, mas mantemos o finally para robustez caso o 'with' não seja usado corretamente em alguma exceção
            conn.close()


# 9. Rota Protegida: Deletar Meu Perfil de Gestor
@gestor_bp.route('/gestor/meu-perfil', methods=['DELETE'])
@token_obrigatorio('gestor')
def deletar_gestor(dados_usuario):
    """
    DELETE /gestor/meu-perfil
    Rota protegida. Permite ao gestor logado deletar sua própria conta.
    Requer: Token JWT válido no cabeçalho Authorization.
    Retorna: Mensagem de sucesso ou erro (404, 409, 500).
    """
    gestor_id = dados_usuario.get('gestor_id')

    conn = get_db_connection()
    if conn is None:
        return jsonify({"error": "Falha na conexão com o banco de dados"}), 500

    try:
        cur = conn.cursor()

        # Deletar o gestor
        query = "DELETE FROM gestores WHERE gestor_id = %s;"
        cur.execute(query, (gestor_id, ))

        if cur.rowcount == 0:
            conn.rollback()
            return jsonify({"error":
                            "Gestor não encontrado para deleção."}), 404

        conn.commit()
        cur.close()

        return jsonify({"message":
                            "Conta de gestor deletada com sucesso."}), 200

    except Exception as e:
        conn.rollback()
        print(f"Erro ao deletar gestor: {e}")
        # Nota: Se o gestor tiver lojas associadas, a deleção pode falhar devido à FK.
        if "foreign key constraint" in str(e).lower():
            return jsonify({
                "error":
                "Não é possível deletar a conta: Você possui lojas cadastradas. Por favor, remova todas as lojas primeiro."
            }), 409

        return jsonify(
            {"error": f"Erro interno ao deletar gestor. Detalhe: {e}"}), 500

    finally:
        if conn:
            conn.close()


# 10. Rota: Servir Foto de Perfil do Gestor
@gestor_bp.route("/gestor/foto/<int:gestor_id>", methods=["GET"])
def obter_foto_gestor(gestor_id):
    """
    GET /gestor/foto/<gestor_id>
    Retorna a foto de perfil do gestor a partir do Object Storage.
    Requer: O ID do gestor na URL.
    Retorna: O arquivo de imagem binário (Content-Type apropriado) ou erro (404, 500).
    """
    conn = get_db_connection()
    if conn is None:
        return jsonify({"error": "Falha na conexão com o banco de dados"}), 500

    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT foto_perfil FROM gestores WHERE gestor_id = %s;",
            (gestor_id,)
        )
        resultado = cur.fetchone()
        cur.close()

        if not resultado or not resultado[0]:
            return jsonify({"error": "Foto não encontrada"}), 404

        foto_nome = resultado[0]

        # Baixar foto do storage
        foto_bytes = client.download_as_bytes(foto_nome)

        # Determinar o tipo MIME baseado na extensão
        extensao = os.path.splitext(foto_nome)[1].lower()
        mime_types = {
            ".jpg": "image/jpeg",
            ".jpeg": "image/jpeg",
            ".png": "image/png",
            ".gif": "image/gif",
            ".webp": "image/webp"
        }
        mime_type = mime_types.get(extensao, "image/jpeg")

        return send_file(
            BytesIO(foto_bytes),
            mimetype=mime_type,
            as_attachment=False
        )

    except Exception as e:
        print(f"Erro ao obter foto do gestor: {e}")
        return jsonify({"error": "Erro ao carregar foto"}), 500

    finally:
        if conn:
            conn.close()

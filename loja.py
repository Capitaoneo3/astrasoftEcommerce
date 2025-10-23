import os
from io import BytesIO

import psycopg2
from flask import Blueprint, jsonify, request, send_file
from replit.object_storage import Client  # Importar para gestão de arquivos

from auth import token_obrigatorio
from banco import get_db_connection

# Instância do Object Storage Client
client = Client() # Instância do client para uploads/downloads

# Definição do Blueprint
loja_bp = Blueprint('loja', __name__)


# Rota 7: Criar uma nova Loja (Mantida)
@loja_bp.route('/loja', methods=['POST'])
@token_obrigatorio(role_necessaria='gestor') # 🛡️ Acesso somente para gestores
def criar_loja(dados_usuario): # Recebe o payload do token
    """Cria uma nova loja, associando-a ao gestor autenticado."""
    # O ID do gestor é pego diretamente do payload do token
    gestor_id_logado = dados_usuario.get('gestor_id')

    data = request.get_json()
    nome_loja = data.get('nome_loja')

    required_fields = [
        'nome_loja', 'endereco_rua', 'endereco_cidade', 'endereco_estado',
        'endereco_cep'
    ]
    if not all(field in data for field in required_fields):
        return jsonify({
            "error":
            "Dados da loja incompletos. Verifique nome, rua, cidade, estado e CEP."
        }), 400

    conn = get_db_connection()
    if conn is None:
        return jsonify({"error": "Falha na conexão com o banco de dados"}), 500

    try:
        cur = conn.cursor()
        # Note que a coluna foto_perfil será NULL por padrão.
        query = """
            INSERT INTO lojas (gestor_id, nome_loja, endereco_rua, endereco_cidade, endereco_estado, endereco_cep)
            VALUES (%s, %s, %s, %s, %s, %s)
            RETURNING loja_id, gestor_id, nome_loja, descricao, endereco_rua, endereco_cidade, endereco_estado, endereco_cep, latitude, longitude, data_criacao, foto_perfil;
        """
        cur.execute(query, (gestor_id_logado, nome_loja, data['endereco_rua'],
                             data['endereco_cidade'], data['endereco_estado'],
                             data['endereco_cep']))

        resultado_completo = cur.fetchone()

        if resultado_completo is None:
            raise Exception(
                "O banco de dados não retornou os dados da loja após a inserção.")

        # Mapeamento do resultado
        loja_criada = {
            "loja_id": resultado_completo[0],
            "gestor_id": resultado_completo[1],
            "nome_loja": resultado_completo[2],
            "descricao": resultado_completo[3],
            "endereco_rua": resultado_completo[4],
            "endereco_cidade": resultado_completo[5],
            "endereco_estado": resultado_completo[6],
            "endereco_cep": resultado_completo[7],
            "latitude": resultado_completo[8],
            "longitude": resultado_completo[9],
            "data_criacao": resultado_completo[10].isoformat() if resultado_completo[10] else None,
            "foto_perfil": resultado_completo[11] # Novo campo
        }

        conn.commit()
        cur.close()

        return jsonify({
            "message": "Loja criada com sucesso",
            "loja": loja_criada
        }), 201

    except psycopg2.errors.UniqueViolation:
        conn.rollback()
        return jsonify({
            "error":
            "Uma loja com este nome já existe ou violação de restrição de unicidade."
        }), 409
    except Exception as e:
        conn.rollback()
        print(f"Erro ao criar loja: {e}")
        return jsonify({"error":
                        f"Erro interno ao criar loja. Detalhe: {e}"}), 500

    finally:
        if conn:
            conn.close()


# NOVO: Rota Protegida: Atualizar Loja (Incluindo Foto)
@loja_bp.route('/loja/<int:loja_id>', methods=['PUT'])
@token_obrigatorio(role_necessaria='gestor')
def atualizar_loja(dados_usuario, loja_id):
    """
    PUT /loja/<loja_id>
    Rota protegida. Permite ao gestor logado atualizar os dados de uma de suas lojas.
    Inclui lógica para upload, substituição e deleção de foto de perfil da loja no Object Storage.
    Requer: Token JWT válido e dados de formulário (incluindo foto_perfil opcionalmente).
    Retorna: Mensagem de sucesso ou erro (400, 403, 404, 500).
    """
    gestor_id_logado = dados_usuario.get('gestor_id')

    # Usamos request.form para campos de texto e request.files para o arquivo (multipart/form-data)
    data = request.form if request.form else request.get_json() or {}
    foto = request.files.get('foto_perfil')

    updates = []
    valores = []

    # Processar campos de texto
    campos_permitidos = [
        'nome_loja', 'descricao', 'endereco_rua', 'endereco_cidade',
        'endereco_estado', 'endereco_cep', 'latitude', 'longitude'
    ]

    for campo in campos_permitidos:
        valor = data.get(campo)
        if valor is not None:
            updates.append(f"{campo} = %s")
            valores.append(valor)

    conn = get_db_connection()
    if conn is None:
        return jsonify({"error": "Falha na conexão com o banco de dados"}), 500

    try:
        with conn:
            with conn.cursor() as cur:
                # 1. VERIFICAR PROPRIEDADE DA LOJA
                cur.execute(
                    "SELECT gestor_id, foto_perfil FROM lojas WHERE loja_id = %s;",
                    (loja_id,)
                )
                resultado_propriedade = cur.fetchone()

                if not resultado_propriedade:
                    return jsonify({"error": "Loja não encontrada."}), 404

                gestor_id_dono, foto_antiga = resultado_propriedade

                # Check 403 Forbidden: O gestor logado é o dono?
                if gestor_id_dono != gestor_id_logado:
                    return jsonify({"error": "Acesso negado. Você não é o gestor desta loja."}), 403


                # --- Lógica de Upload de Foto (semelhante ao gestor.py) ---
                if foto:
                    # 2. Deletar foto antiga do storage se existir
                    if foto_antiga:
                        try:
                            client.delete(foto_antiga, ignore_not_found=True)
                        except Exception as e:
                            print(f"Aviso: Erro ao deletar foto antiga da loja {loja_id}: {e}")

                    # 3. Fazer upload da nova foto
                    extensao = os.path.splitext(foto.filename)[1] if foto.filename else '.jpg'
                    nome_arquivo = f"loja_{loja_id}_perfil{extensao}"

                    # Upload do arquivo para o storage
                    foto.seek(0) # Garantir que o ponteiro está no início, caso tenha sido lido antes
                    client.upload_from_bytes(nome_arquivo, foto.read())

                    # 4. Adicionar o caminho da nova foto aos updates do DB
                    updates.append("foto_perfil = %s")
                    valores.append(nome_arquivo)

                # --- Verificação de Updates ---
                if not updates:
                    return jsonify({
                        "error":
                        "Nenhum dado (texto ou foto) fornecido para atualização."
                    }), 400

                # --- Execução do SQL UPDATE ---
                query = f"""
                    UPDATE lojas
                    SET {', '.join(updates)}
                    WHERE loja_id = %s AND gestor_id = %s;
                """
                # Adiciona o ID da loja e o ID do gestor para o filtro WHERE
                valores.extend([loja_id, gestor_id_logado])

                cur.execute(query, tuple(valores))

                conn.commit()

        # Resposta de Sucesso
        return jsonify({"message":
                        f"Loja {loja_id} atualizada com sucesso."}), 200

    except Exception as e:
        conn.rollback()
        print(f"Erro ao atualizar loja {loja_id}: {e}")
        return jsonify(
            {"error": "Erro interno ao atualizar loja."}), 500

    finally:
        if conn:
            conn.close()

# NOVO: Rota Pública: Servir Foto de Perfil da Loja
@loja_bp.route("/loja/foto/<int:loja_id>", methods=["GET"])
def obter_foto_loja(loja_id):
    """
    GET /loja/foto/<loja_id>
    Retorna a foto de perfil da loja a partir do Object Storage.
    Requer: O ID da loja na URL.
    Retorna: O arquivo de imagem binário (Content-Type apropriado) ou erro (404, 500).
    """
    conn = get_db_connection()
    if conn is None:
        return jsonify({"error": "Falha na conexão com o banco de dados"}), 500

    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT foto_perfil FROM lojas WHERE loja_id = %s;",
            (loja_id,)
        )
        resultado = cur.fetchone()
        cur.close()

        if not resultado or not resultado[0]:
            # Retorna 404 se não houver registro ou a coluna foto_perfil for NULL
            return jsonify({"error": "Foto da loja não encontrada"}), 404

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
        print(f"Erro ao obter foto da loja: {e}")
        return jsonify({"error": "Erro ao carregar foto"}), 500

    finally:
        if conn:
            conn.close()


# 8. Rota Pública: Listar Todas as Lojas (ATUALIZADA para retornar todos os campos)
@loja_bp.route('/lojas', methods=['GET'])
def listar_todas_lojas():
    """Retorna uma lista de todas as lojas disponíveis no banco de dados, com todos os campos (incluindo foto_perfil)."""
    conn = get_db_connection()
    if conn is None:
        return jsonify({"error": "Falha na conexão com o banco de dados"}), 500

    try:
        cur = conn.cursor()
        # MUDANÇA: Seleciona TODOS os campos (incluindo foto_perfil)
        query = """
            SELECT loja_id, nome_loja, descricao, endereco_rua, endereco_cidade,
                   endereco_estado, endereco_cep, latitude, longitude, data_criacao, foto_perfil
            FROM lojas
            ORDER BY nome_loja;
        """
        cur.execute(query)
        lojas_data = cur.fetchall()
        cur.close()

        # MUDANÇA: Mapeamento de todos os campos
        lojas = [{
            "loja_id": row[0],
            "nome_loja": row[1],
            "descricao": row[2],
            "endereco_rua": row[3],
            "endereco_cidade": row[4],
            "endereco_estado": row[5],
            "endereco_cep": row[6],
            "latitude": row[7],
            "longitude": row[8],
            "data_criacao": row[9].isoformat() if row[9] else None,
            "foto_perfil": row[10] # Novo campo
        } for row in lojas_data]

        return jsonify({"lojas": lojas}), 200

    except Exception as e:
        print(f"Erro ao listar todas as lojas: {e}")
        return jsonify({"error": "Erro interno ao buscar lojas."}), 500

    finally:
        if conn:
            conn.close()


# 9. Rota Protegida: Listar Lojas do Gestor Logado (ATUALIZADA para todos os campos)
@loja_bp.route('/gestor/minhas-lojas', methods=['GET'])
@token_obrigatorio(role_necessaria='gestor') # 🛡️ Acesso somente para gestores
def listar_lojas_do_gestor(dados_usuario):
    """Retorna uma lista de lojas cadastradas pelo gestor autenticado, com todos os detalhes (incluindo foto_perfil)."""
    gestor_id_logado = dados_usuario.get('gestor_id')

    conn = get_db_connection()
    if conn is None:
        return jsonify({"error": "Falha na conexão com o banco de dados"}), 500

    try:
        cur = conn.cursor()

        # MUDANÇA: Seleciona TODOS os campos da tabela 'lojas'
        query = """
            SELECT loja_id, gestor_id, nome_loja, descricao, endereco_rua,
                   endereco_cidade, endereco_estado, endereco_cep, latitude,
                   longitude, data_criacao, foto_perfil
            FROM lojas
            WHERE gestor_id = %s
            ORDER BY nome_loja;
        """
        cur.execute(query, (gestor_id_logado, ))
        lojas_data = cur.fetchall()
        cur.close()

        # MUDANÇA: Ajustar o mapeamento para incluir TODOS os campos
        lojas = [{
            "loja_id": row[0],
            "gestor_id": row[1],
            "nome_loja": row[2],
            "descricao": row[3],      # NOVO CAMPO
            "endereco_rua": row[4],
            "endereco_cidade": row[5],
            "endereco_estado": row[6],
            "endereco_cep": row[7],
            "latitude": row[8],        # NOVO CAMPO
            "longitude": row[9],       # NOVO CAMPO
            "data_criacao": row[10].isoformat() if row[10] else None,
            "foto_perfil": row[11] # Novo campo
        } for row in lojas_data]

        return jsonify({"minhas_lojas": lojas}), 200

    except Exception as e:
        print(f"Erro ao listar lojas do gestor: {e}")
        return jsonify({"error": "Erro interno ao buscar suas lojas."}), 500

    finally:
        if conn:
            conn.close()

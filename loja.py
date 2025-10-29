import os  # Necessário para manipulação de caminhos de arquivo (extensao)
from io import BytesIO  # Importação necessária para send_file

import psycopg2
from flask import Blueprint, jsonify, request, send_file

# Assumindo que estas importações estão corretas no seu ambiente
from auth import token_obrigatorio
from banco import get_db_connection
from gestor import client

# Definição do Blueprint
loja_bp = Blueprint('loja', __name__)


# Rota 7 (Atualizada): Criar uma nova Loja (POST)
@loja_bp.route('/loja', methods=['POST'])
@token_obrigatorio(role_necessaria='gestor') # 🛡️ Acesso somente para gestores
def criar_loja(dados_usuario): # Recebe o payload do token
    """Cria uma nova loja, associando-a ao gestor autenticado. 'descricao' é opcional."""
    gestor_id_logado = dados_usuario.get('gestor_id')

    data = request.get_json()
    nome_loja = data.get('nome_loja')
    # NOVO: O campo 'descricao' é opcional e pode ser None
    descricao = data.get('descricao') 

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
        query = """
            INSERT INTO lojas (gestor_id, nome_loja, descricao, endereco_rua, endereco_cidade, endereco_estado, endereco_cep) 
            VALUES (%s, %s, %s, %s, %s, %s, %s) 
            RETURNING loja_id, gestor_id, nome_loja, descricao, endereco_rua, endereco_cidade, endereco_estado, endereco_cep, latitude, longitude, data_criacao;
        """
        # ATUALIZAÇÃO: Inclusão do 'descricao' nos valores
        cur.execute(query, (gestor_id_logado, nome_loja, descricao, data['endereco_rua'],
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
            "data_criacao": resultado_completo[10].isoformat() if resultado_completo[10] else None
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


# 8. Rota Pública: Listar Todas as Lojas
@loja_bp.route('/lojas', methods=['GET'])
def listar_todas_lojas():
    """Retorna uma lista de todas as lojas disponíveis no banco de dados, com todos os campos."""
    conn = get_db_connection()
    if conn is None:
        return jsonify({"error": "Falha na conexão com o banco de dados"}), 500

    try:
        cur = conn.cursor()
        query = """
            SELECT loja_id, nome_loja, descricao, endereco_rua, endereco_cidade, 
                   endereco_estado, endereco_cep, latitude, longitude, data_criacao 
            FROM lojas
            ORDER BY nome_loja;
        """
        cur.execute(query)
        lojas_data = cur.fetchall()
        cur.close()

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
            "data_criacao": row[9].isoformat() if row[9] else None
        } for row in lojas_data]

        return jsonify({"lojas": lojas}), 200

    except Exception as e:
        print(f"Erro ao listar todas as lojas: {e}")
        return jsonify({"error": "Erro interno ao buscar lojas."}), 500

    finally:
        if conn:
            conn.close()


# 9. Rota Protegida: Listar Lojas do Gestor Logado
@loja_bp.route('/gestor/minhas-lojas', methods=['GET'])
@token_obrigatorio(role_necessaria='gestor') # 🛡️ Acesso somente para gestores
def listar_lojas_do_gestor(dados_usuario):
    """Retorna uma lista de lojas cadastradas pelo gestor autenticado, com todos os detalhes."""
    gestor_id_logado = dados_usuario.get('gestor_id')

    conn = get_db_connection()
    if conn is None:
        return jsonify({"error": "Falha na conexão com o banco de dados"}), 500

    try:
        cur = conn.cursor()

        query = """
            SELECT loja_id, gestor_id, nome_loja, descricao, endereco_rua, 
                   endereco_cidade, endereco_estado, endereco_cep, latitude, 
                   longitude, data_criacao
            FROM lojas
            WHERE gestor_id = %s
            ORDER BY nome_loja;
        """
        cur.execute(query, (gestor_id_logado, ))
        lojas_data = cur.fetchall()
        cur.close()

        lojas = [{
            "loja_id": row[0],
            "gestor_id": row[1],
            "nome_loja": row[2],
            "descricao": row[3],      
            "endereco_rua": row[4],
            "endereco_cidade": row[5],
            "endereco_estado": row[6],
            "endereco_cep": row[7],
            "latitude": row[8],          
            "longitude": row[9],         
            "data_criacao": row[10].isoformat() if row[10] else None
        } for row in lojas_data]

        return jsonify({"minhas_lojas": lojas}), 200

    except Exception as e:
        print(f"Erro ao listar lojas do gestor: {e}")
        return jsonify({"error": "Erro interno ao buscar suas lojas."}), 500

    finally:
        if conn:
            conn.close()

# 10. Deletar uma Loja por ID
@loja_bp.route('/loja/<int:loja_id>', methods=['DELETE'])
@token_obrigatorio(role_necessaria='gestor') # 🛡️ Acesso somente para gestores
def deletar_loja(loja_id, dados_usuario): 
    """Exclui uma loja específica pelo ID, garantindo que o gestor autenticado é o proprietário."""
    gestor_id_logado = dados_usuario.get('gestor_id')

    conn = get_db_connection()
    if conn is None:
        return jsonify({"error": "Falha na conexão com o banco de dados"}), 500

    try:
        cur = conn.cursor()

        query_delete = """
            DELETE FROM lojas
            WHERE loja_id = %s AND gestor_id = %s
            RETURNING nome_loja;
        """

        cur.execute(query_delete, (loja_id, gestor_id_logado))
        nome_loja_deletada = cur.fetchone()

        if nome_loja_deletada is None:
            conn.rollback()
            cur.close()

            # Verificação extra para dar um feedback mais preciso:
            cur_check = conn.cursor()
            cur_check.execute("SELECT loja_id FROM lojas WHERE loja_id = %s;", (loja_id,))
            loja_existe = cur_check.fetchone()
            cur_check.close()

            if loja_existe:
                return jsonify({
                    "error": "Acesso negado. Você só pode deletar lojas que gerencia."
                }), 403 # Forbidden
            else:
                return jsonify({
                    "error": f"Loja com ID {loja_id} não encontrada."
                }), 404 # Not Found

        nome_loja = nome_loja_deletada[0]
        conn.commit()
        cur.close()

        return jsonify({
            "message": f"Loja '{nome_loja}' (ID: {loja_id}) deletada com sucesso."
        }), 200

    except Exception as e:
        conn.rollback()
        print(f"Erro ao deletar loja: {e}")
        return jsonify({"error": f"Erro interno ao deletar loja. Detalhe: {e}"}), 500

    finally:
        if conn:
            conn.close()


# 📌 Rota 11 (Atualização): Atualizar uma Loja (PUT)
@loja_bp.route('/loja/<int:loja_id>', methods=['PUT'])
@token_obrigatorio(role_necessaria='gestor') # 🛡️ Acesso somente para gestores
def atualizar_loja(loja_id, dados_usuario): # Recebe o ID da loja e o payload do token
    """
    Atualiza dados da loja e a imagem de perfil (foto_loja).
    Requer multipart/form-data e acesso do gestor proprietário.
    O campo 'descricao' é opcional.
    """
    gestor_id_logado = dados_usuario.get('gestor_id')

    # 1. Captura dos dados do formulário (multipart/form-data)
    nome_loja = request.form.get('nome_loja')
    # O campo 'descricao' já está corretamente tratado como opcional
    descricao = request.form.get('descricao') 
    endereco_rua = request.form.get('endereco_rua')
    endereco_cidade = request.form.get('endereco_cidade')
    endereco_estado = request.form.get('endereco_estado')
    endereco_cep = request.form.get('endereco_cep')
    latitude = request.form.get('latitude')
    longitude = request.form.get('longitude')

    foto_loja = request.files.get('foto_loja') # Captura o arquivo da imagem

    updates = []
    valores = []

    # 2. Montagem dos campos a serem atualizados
    if nome_loja:
        updates.append("nome_loja = %s")
        valores.append(nome_loja)

    # TRATAMENTO CORRETO DE CAMPO OPCIONAL:
    # 'is not None' permite que o usuário envie a descrição com string vazia ou explicitamente nula (se permitido pelo BD)
    if descricao is not None: 
        updates.append("descricao = %s")
        valores.append(descricao)

    if endereco_rua:
        updates.append("endereco_rua = %s")
        valores.append(endereco_rua)
    if endereco_cidade:
        updates.append("endereco_cidade = %s")
        valores.append(endereco_cidade)
    if endereco_estado:
        updates.append("endereco_estado = %s")
        valores.append(endereco_estado)
    if endereco_cep:
        updates.append("endereco_cep = %s")
        valores.append(endereco_cep)
    if latitude is not None:
        updates.append("latitude = %s")
        valores.append(latitude)
    if longitude is not None:
        updates.append("longitude = %s")
        valores.append(longitude)

    # 3. Verificação preliminar antes de abrir a conexão
    if not updates and not foto_loja:
        return jsonify({
            "error": "Nenhum dado fornecido para atualização. Forneça pelo menos um campo ou uma imagem."
        }), 400

    conn = get_db_connection()
    if conn is None:
        return jsonify({"error": "Falha na conexão com o banco de dados"}), 500

    try:
        cur = conn.cursor()

        # --- Lógica de Upload de Foto ---
        if foto_loja:
            # 3.1. Buscar foto antiga do cliente para deletar e verificar propriedade
            cur.execute(
                "SELECT foto_loja, gestor_id FROM lojas WHERE loja_id = %s;",
                (loja_id, ))
            resultado_loja = cur.fetchone()

            if not resultado_loja:
                conn.rollback()
                return jsonify({"error": f"Loja com ID {loja_id} não encontrada."}), 404

            foto_antiga = resultado_loja[0]
            proprietario_id = resultado_loja[1]

            # 3.2. Validação de Propriedade
            if proprietario_id != gestor_id_logado:
                conn.rollback()
                return jsonify({
                    "error": "Acesso negado. Você só pode atualizar lojas que gerencia."
                }), 403 # Forbidden

            # 3.3. Deletar foto antiga do storage se existir
            if foto_antiga:
                try:
                    client.delete(foto_antiga, ignore_not_found=True)
                except Exception as e:
                    print(
                        f"Aviso: Erro ao deletar foto antiga, mas a atualização continua: {e}"
                    )

            # 3.4. Fazer upload da nova foto
            extensao = os.path.splitext(
                foto_loja.filename)[1] if foto_loja.filename else '.jpg'
            nome_arquivo = f"loja_{loja_id}_perfil{extensao}"

            client.upload_from_bytes(nome_arquivo, foto_loja.read())

            # 3.5. Adicionar o caminho da nova foto aos updates do DB
            updates.append("foto_loja = %s")
            valores.append(nome_arquivo)

        else:
            # Se não houver arquivo, verifica se o gestor é o proprietário antes de atualizar
            cur.execute("SELECT gestor_id FROM lojas WHERE loja_id = %s;", (loja_id,))
            resultado_loja = cur.fetchone()

            if not resultado_loja:
                conn.rollback()
                return jsonify({"error": f"Loja com ID {loja_id} não encontrada."}), 404

            proprietario_id = resultado_loja[0]

            if proprietario_id != gestor_id_logado:
                conn.rollback()
                return jsonify({
                    "error": "Acesso negado. Você só pode atualizar lojas que gerencia."
                }), 403 # Forbidden

        # --- Execução do SQL UPDATE ---
        query = f"""
            UPDATE lojas
            SET {', '.join(updates)}
            WHERE loja_id = %s;
        """
        # Adiciona o ID da loja para o filtro WHERE
        valores.append(loja_id)

        cur.execute(query, tuple(valores))

        conn.commit()
        cur.close()

        return jsonify(
            {"message": f"Loja (ID: {loja_id}) atualizada com sucesso."}), 200


    except Exception as e:
        conn.rollback()
        print(f"Erro ao atualizar loja: {e}")
        return jsonify(
            {"error": f"Erro interno ao atualizar loja. Detalhe: {e}"}), 500

    finally:
        if conn:
            conn.close()



# 12: Servir Foto de Perfil da Loja
@loja_bp.route("/loja/foto/<int:loja_id>", methods=["GET"])
def obter_foto_loja(loja_id):
    """
    Busca o caminho da foto da loja no DB e serve o arquivo do Object Storage.
    Esta rota é pública.
    """
    conn = get_db_connection()
    if conn is None:
        return jsonify({"error": "Falha na conexão com o banco de dados"}), 500

    try:
        cur = conn.cursor()

        # MUDANÇA 1: Busca na tabela 'lojas' pelo 'loja_id'
        cur.execute("SELECT foto_loja FROM lojas WHERE loja_id = %s;",
                    (loja_id, ))
        resultado = cur.fetchone()
        cur.close()

        # 1. Verifica se a loja foi encontrada e se tem um caminho de foto
        if not resultado or not resultado[0]:
            return jsonify({"error": "Foto da loja não encontrada"}), 404

        foto_nome = resultado[0]

        # 2. Baixar foto do storage (Requer 'client' do Object Storage)
        try:
            # ASSUME que 'client.download_as_bytes' está disponível
            foto_bytes = client.download_as_bytes(foto_nome)
        except Exception as e:
            print(f"Erro ao baixar foto da loja do storage: {e}")
            return jsonify(
                {"error": "Arquivo de foto não encontrado no storage"}), 404

        # 3. Determinar o tipo MIME baseado na extensão
        extensao = os.path.splitext(foto_nome)[1].lower()
        mime_types = {
            ".jpg": "image/jpeg",
            ".jpeg": "image/jpeg",
            ".png": "image/png",
            ".gif": "image/gif",
            ".webp": "image/webp"
        }
        # Padrão: image/jpeg se a extensão for desconhecida
        mime_type = mime_types.get(extensao, "image/jpeg")

        # 4. Retornar o arquivo de bytes
        # send_file exige um objeto tipo arquivo, por isso usamos BytesIO
        return send_file(BytesIO(foto_bytes),
                         mimetype=mime_type,
                         as_attachment=False)

    except Exception as e:
        print(f"Erro ao obter foto da loja: {e}")
        return jsonify(
            {"error":
             "Erro interno ao carregar foto da loja. Detalhe: {e}"}), 500

    finally:
        if conn:
            conn.close()
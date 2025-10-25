import psycopg2
from flask import Blueprint, jsonify, request

from auth import token_obrigatorio
from banco import get_db_connection

# Definição do Blueprint
loja_bp = Blueprint('loja', __name__)


# Rota 7 (Atualizada): Criar uma nova Loja
@loja_bp.route('/loja', methods=['POST'])
@token_obrigatorio(role_necessaria='gestor')  # 🛡️ Acesso somente para gestores
def criar_loja(dados_usuario):  # Recebe o payload do token
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
        query = """
            INSERT INTO lojas (gestor_id, nome_loja, endereco_rua, endereco_cidade, endereco_estado, endereco_cep) 
            VALUES (%s, %s, %s, %s, %s, %s) 
            RETURNING loja_id;
        """
        cur.execute(query, (gestor_id_logado, nome_loja, data['endereco_rua'],
                            data['endereco_cidade'], data['endereco_estado'],
                            data['endereco_cep']))

        resultado = cur.fetchone()

        if resultado is None:
            raise Exception(
                "O banco de dados não retornou o ID da loja após a inserção.")

        loja_id = resultado[0]

        conn.commit()
        cur.close()

        return jsonify({
            "message": "Loja criada com sucesso",
            "loja_id": loja_id,
            "gestor_id": gestor_id_logado
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
    """Retorna uma lista de todas as lojas disponíveis no banco de dados."""
    conn = get_db_connection()
    if conn is None:
        return jsonify({"error": "Falha na conexão com o banco de dados"}), 500

    try:
        cur = conn.cursor()
        # Seleciona as colunas públicas da loja
        query = """
            SELECT loja_id, nome_loja, endereco_cidade, endereco_estado, data_criacao 
            FROM lojas
            ORDER BY nome_loja;
        """
        cur.execute(query)
        lojas_data = cur.fetchall()
        cur.close()

        lojas = [{
            "loja_id": row[0],
            "nome_loja": row[1],
            "cidade": row[2],
            "estado": row[3],
            "data_criacao": row[4].isoformat() if row[4] else None
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
@token_obrigatorio(role_necessaria='gestor')  # 🛡️ Acesso somente para gestores
def listar_lojas_do_gestor(dados_usuario):
    """Retorna uma lista de lojas cadastradas pelo gestor autenticado."""
    # O ID do gestor é pego diretamente do payload do token
    gestor_id_logado = dados_usuario.get('gestor_id')

    conn = get_db_connection()
    if conn is None:
        return jsonify({"error": "Falha na conexão com o banco de dados"}), 500

    try:
        cur = conn.cursor()
        # Seleciona lojas filtrando pelo gestor_id
        query = """
            SELECT loja_id, nome_loja, endereco_cidade, endereco_estado, data_criacao 
            FROM lojas
            WHERE gestor_id = %s
            ORDER BY nome_loja;
        """
        cur.execute(query, (gestor_id_logado, ))
        lojas_data = cur.fetchall()
        cur.close()

        lojas = [{
            "loja_id": row[0],
            "nome_loja": row[1],
            "cidade": row[2],
            "estado": row[3],
            "data_criacao": row[4].isoformat() if row[4] else None
        } for row in lojas_data]

        return jsonify({"minhas_lojas": lojas}), 200

    except Exception as e:
        print(f"Erro ao listar lojas do gestor: {e}")
        return jsonify({"error": "Erro interno ao buscar suas lojas."}), 500

    finally:
        if conn:
            conn.close()


# Continuação de loja.py


# 10. Rota Protegida: Atualizar uma Loja
@loja_bp.route('/loja/<int:loja_id>', methods=['PUT'])
@token_obrigatorio(role_necessaria='gestor')
def atualizar_loja(dados_usuario, loja_id):
    """Atualiza os dados de uma loja específica, garantindo que o gestor logado é o proprietário."""
    gestor_id_logado = dados_usuario.get('gestor_id')
    data = request.get_json()

    # Campos que podem ser atualizados
    campos_permitidos = [
        'nome_loja', 'endereco_rua', 'endereco_cidade', 'endereco_estado',
        'endereco_cep'
    ]

    # Cria a string de SET para a query, apenas com os campos fornecidos no JSON
    updates = []
    valores = []
    for campo in campos_permitidos:
        if campo in data:
            updates.append(f"{campo} = %s")
            valores.append(data[campo])

    if not updates:
        return jsonify(
            {"error": "Nenhum dado de loja fornecido para atualização."}), 400

    conn = get_db_connection()
    if conn is None:
        return jsonify({"error": "Falha na conexão com o banco de dados"}), 500

    try:
        cur = conn.cursor()

        # A query de atualização deve incluir o filtro por loja_id E gestor_id
        query = f"""
            UPDATE lojas 
            SET {', '.join(updates)}
            WHERE loja_id = %s AND gestor_id = %s
            RETURNING loja_id;
        """
        # Adiciona loja_id e gestor_id no final da lista de valores para a cláusula WHERE
        valores.extend([loja_id, gestor_id_logado])

        cur.execute(query, tuple(valores))

        if cur.rowcount == 0:
            # Se não afetou nenhuma linha, ou a loja não existe, ou o gestor não é o dono
            conn.rollback()
            return jsonify({
                "error":
                "Loja não encontrada ou você não tem permissão para editar esta loja."
            }), 403  # Forbidden ou Not Found, 403 é mais seguro

        conn.commit()
        cur.close()

        return jsonify(
            {"message": f"Loja ID {loja_id} atualizada com sucesso."}), 200

    except psycopg2.errors.UniqueViolation:
        conn.rollback()
        return jsonify({
            "error":
            "Uma loja com este nome já existe ou violação de restrição de unicidade."
        }), 409
    except Exception as e:
        conn.rollback()
        print(f"Erro ao atualizar loja ID {loja_id}: {e}")
        return jsonify(
            {"error": f"Erro interno ao atualizar loja. Detalhe: {e}"}), 500

    finally:
        if conn:
            conn.close()


# 11. Rota Protegida: Deletar uma Loja
@loja_bp.route('/loja/<int:loja_id>', methods=['DELETE'])
@token_obrigatorio(role_necessaria='gestor')
def deletar_loja(dados_usuario, loja_id):
    """Deleta uma loja específica, garantindo que o gestor logado é o proprietário."""
    gestor_id_logado = dados_usuario.get('gestor_id')

    conn = get_db_connection()
    if conn is None:
        return jsonify({"error": "Falha na conexão com o banco de dados"}), 500

    try:
        cur = conn.cursor()

        # A query de deleção deve incluir o filtro por loja_id E gestor_id
        query = """
            DELETE FROM lojas 
            WHERE loja_id = %s AND gestor_id = %s;
        """
        cur.execute(query, (loja_id, gestor_id_logado))

        if cur.rowcount == 0:
            # Se não afetou nenhuma linha, ou a loja não existe, ou o gestor não é o dono
            conn.rollback()
            return jsonify({
                "error":
                "Loja não encontrada ou você não tem permissão para deletar esta loja."
            }), 403  # Forbidden ou Not Found

        conn.commit()
        cur.close()

        return jsonify({"message":
                        f"Loja ID {loja_id} deletada com sucesso."}), 200

    except Exception as e:
        conn.rollback()
        print(f"Erro ao deletar loja ID {loja_id}: {e}")
        # psycopg2.errors.ForeignKeyViolation pode ocorrer se houver produtos ou pedidos associados
        if "foreign key constraint" in str(e).lower():
            return jsonify({
                "error":
                "Não é possível deletar a loja: existem dados (produtos/pedidos) associados a ela."
            }), 409

        return jsonify(
            {"error": f"Erro interno ao deletar loja. Detalhe: {e}"}), 500

    finally:
        if conn:
            conn.close()

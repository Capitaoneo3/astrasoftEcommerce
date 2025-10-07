import psycopg2
from flask import Blueprint, jsonify, request

from auth import token_obrigatorio
from banco import get_db_connection

# Definição do Blueprint
loja_bp = Blueprint('loja', __name__)


# Rota 7 (Atualizada): Criar uma nova Loja
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
@token_obrigatorio(role_necessaria='gestor') # 🛡️ Acesso somente para gestores
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

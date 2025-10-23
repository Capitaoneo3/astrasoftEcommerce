import psycopg2
from flask import Blueprint, jsonify, request

from auth import token_obrigatorio
from banco import get_db_connection

# Definição do Blueprint
loja_bp = Blueprint('loja', __name__)


# Rota 7 (Atualizada): Criar uma nova Loja (Mantida)
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
            RETURNING loja_id, gestor_id, nome_loja, descricao, endereco_rua, endereco_cidade, endereco_estado, endereco_cep, latitude, longitude, data_criacao;
        """
        # Adicionei 'descricao', 'latitude', 'longitude' como None/NULL se não vieram no POST.
        # Ajuste a query de INSERT se você estiver passando esses valores.
        # Por simplicidade, vou usar a query original, apenas mudando o RETURNING para retornar mais dados.
        query = """
            INSERT INTO lojas (gestor_id, nome_loja, endereco_rua, endereco_cidade, endereco_estado, endereco_cep) 
            VALUES (%s, %s, %s, %s, %s, %s) 
            RETURNING loja_id, gestor_id, nome_loja, descricao, endereco_rua, endereco_cidade, endereco_estado, endereco_cep, latitude, longitude, data_criacao;
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


# 8. Rota Pública: Listar Todas as Lojas (ATUALIZADA para retornar todos os campos)
@loja_bp.route('/lojas', methods=['GET'])
def listar_todas_lojas():
    """Retorna uma lista de todas as lojas disponíveis no banco de dados, com todos os campos."""
    conn = get_db_connection()
    if conn is None:
        return jsonify({"error": "Falha na conexão com o banco de dados"}), 500

    try:
        cur = conn.cursor()
        # MUDANÇA: Seleciona TODOS os campos (exceto gestor_id, que é sensível e interno)
        # Se gestor_id for considerado público, adicione-o também.
        query = """
            SELECT loja_id, nome_loja, descricao, endereco_rua, endereco_cidade, 
                   endereco_estado, endereco_cep, latitude, longitude, data_criacao 
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
            "data_criacao": row[9].isoformat() if row[9] else None
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
    """Retorna uma lista de lojas cadastradas pelo gestor autenticado, com todos os detalhes."""
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
                   longitude, data_criacao
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
            "descricao": row[3],        # NOVO CAMPO
            "endereco_rua": row[4],
            "endereco_cidade": row[5],
            "endereco_estado": row[6],
            "endereco_cep": row[7],
            "latitude": row[8],         # NOVO CAMPO
            "longitude": row[9],        # NOVO CAMPO
            "data_criacao": row[10].isoformat() if row[10] else None
        } for row in lojas_data]

        return jsonify({"minhas_lojas": lojas}), 200

    except Exception as e:
        print(f"Erro ao listar lojas do gestor: {e}")
        return jsonify({"error": "Erro interno ao buscar suas lojas."}), 500

    finally:
        if conn:
            conn.close()
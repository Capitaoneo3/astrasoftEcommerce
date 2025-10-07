import psycopg2
from flask import g, jsonify, request

from auth import token_obrigatorio
from banco import get_db_connection
from gestor import gestor_bp

# 7. Rota Protegida: Criar uma nova Loja
@gestor_bp.route('/lojas', methods=['POST'])
@token_obrigatorio  # 🛡️ Acesso somente para gestores
def criar_loja():
    """Cria uma nova loja, associando-a ao gestor autenticado."""
    # O ID do gestor é pego do contexto 'g' após a validação do token
    gestor_id_logado = g.user_id

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
            "Um gestor já possui uma loja com este nome ou violação de restrição de unicidade."
        }), 409
    except Exception as e:
        conn.rollback()
        print(f"Erro ao criar loja: {e}")
        return jsonify({"error":
                         f"Erro interno ao criar loja. Detalhe: {e}"}), 500

    finally:
        if conn:
            conn.close()

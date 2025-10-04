import os
from flask import Flask, jsonify, request
import psycopg2
from dotenv import load_dotenv

# 1. Carrega as variáveis de ambiente (credenciais do .env)
load_dotenv()

app = Flask(__name__)


# --- FUNÇÃO DE CONEXÃO AO BANCO DE DADOS ---
def get_db_connection():
    """Estabelece e retorna a conexão com o banco de dados PostgreSQL."""
    try:
        conn = psycopg2.connect(database=os.getenv("DB_NAME"),
                                user=os.getenv("DB_USER"),
                                password=os.getenv("DB_PASS"),
                                host=os.getenv("DB_HOST"),
                                port=os.getenv("DB_PORT"))
        return conn
    except Exception as e:
        print(f"Erro ao conectar ao banco de dados: {e}")
        return None


# --- ROTAS DA API ---


@app.route('/', methods=['GET'])
def home():
    """Rota de boas-vindas para testar se a API está online."""
    return jsonify({
        "message": "API de E-commerce rodando!",
        "status": "online"
    })


# 4. Exemplo de Rota: Listar todos os Gestores
@app.route('/gestores', methods=['GET'])
def listar_gestores():
    conn = get_db_connection()
    if conn is None:
        return jsonify({"error": "Falha na conexão com o banco de dados"}), 500

    try:
        cur = conn.cursor()
        # Consulta simples para trazer todos os gestores
        cur.execute(
            "SELECT gestor_id, nome, email, data_cadastro FROM gestores;")

        # Converte o resultado em uma lista de dicionários
        gestores = [{
            "gestor_id": row[0],
            "nome": row[1],
            "email": row[2],
            "data_cadastro": row[3]
        } for row in cur.fetchall()]

        cur.close()
        return jsonify(gestores)

    except Exception as e:
        print(f"Erro na consulta: {e}")
        return jsonify({"error": "Erro ao buscar gestores"}), 500

    finally:
        conn.close()


# 5. Exemplo de Rota: Criar um novo Gestor (AQUI ENTRA A SEGURANÇA!)
@app.route('/gestores', methods=['POST'])
def criar_gestor():
    data = request.get_json()
    nome = data.get('nome')
    email = data.get('email')
    senha_plana = data.get('senha')  # A senha em texto puro

    # ⚠️ AVISO DE SEGURANÇA: NUNCA armazene a senha em texto puro.
    # Você deve HASHEAR a senha aqui antes de inseri-la no banco.
    # Ex: usando bcrypt. Para o Flask, instale 'Flask-Bcrypt'.
    # Aqui, por simplicidade, usaremos um placeholder:
    senha_hash_placeholder = f"HASH_DO_{senha_plana}"

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
        cur.execute(query, (nome, email, senha_hash_placeholder))
        gestor_id = cur.fetchone()[0]
        conn.commit()
        cur.close()

        return jsonify({
            "message": "Gestor criado com sucesso",
            "gestor_id": gestor_id
        }), 201

    except psycopg2.errors.UniqueViolation:
        # Erro se o email já existe
        return jsonify({"error": "Email já cadastrado."}), 409
    except Exception as e:
        conn.rollback()
        print(f"Erro ao criar gestor: {e}")
        return jsonify({"error": "Erro interno ao criar gestor"}), 500

    finally:
        conn.close()


if __name__ == '__main__':
    # O Replit roda automaticamente, mas é bom ter o if
    app.run(host='0.0.0.0', port=8080)

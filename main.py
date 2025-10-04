import os

import psycopg2
from dotenv import load_dotenv
from flask import Flask, jsonify, request
from flask_bcrypt import Bcrypt

# 1. Carrega as variáveis de ambiente (credenciais do .env)
load_dotenv()

app = Flask(__name__)

bcrypt = Bcrypt(app)


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


# 5. Rota: Criar um novo Gestor (AGORA COM HASHING SEGURO)
@app.route('/gestores', methods=['POST'])
def criar_gestor():
    data = request.get_json()
    nome = data.get('nome')
    email = data.get('email')
    senha_plana = data.get('senha')

    if not all([nome, email, senha_plana]):
        return jsonify({"error": "Nome, email e senha são obrigatórios."}), 400

    # ⭐ IMPLEMENTAÇÃO DO BCRYPT: Cria o hash da senha
    # O encode() transforma a string em bytes, e o decode() a retorna para string para o DB.
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
        # Note que agora usamos a variável 'senha_hash_seguro'
        cur.execute(query, (nome, email, senha_hash_seguro))
        gestor_id = cur.fetchone()[0]
        conn.commit()
        cur.close()

        return jsonify({
            "message": "Gestor criado com sucesso",
            "gestor_id": gestor_id
        }), 201

    except psycopg2.errors.UniqueViolation:
        return jsonify({"error": "Email já cadastrado."}), 409
    except Exception as e:
        conn.rollback()
        print(f"Erro ao criar gestor: {e}")
        return jsonify({"error": "Erro interno ao criar gestor"}), 500

    finally:
        conn.close()


# 6. Nova Rota: Login do Gestor (Verificação de Senha)
@app.route('/login/gestor', methods=['POST'])
def login_gestor():
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
        # 1. Busca o gestor pelo email e recupera a senha hasheada
        cur.execute(
            "SELECT gestor_id, senha_hash FROM gestores WHERE email = %s;",
            (email, ))
        gestor_data = cur.fetchone()
        cur.close()

        if gestor_data is None:
            # Não revela se o erro foi o email ou a senha
            return jsonify({"error": "Credenciais inválidas."}), 401

        gestor_id, senha_hash_do_db = gestor_data

        # ⭐ IMPLEMENTAÇÃO DO BCRYPT: Compara a senha plana com o hash do banco
        if bcrypt.check_password_hash(senha_hash_do_db, senha_plana):
            # Se a senha for válida, o login é bem-sucedido.
            # ⚠️ AQUI VOCÊ DEVERIA GERAR UM JWT (JSON WEB TOKEN) para o gestor.
            return jsonify({
                "message": "Login bem-sucedido!",
                "gestor_id": gestor_id
            }), 200
        else:
            return jsonify({"error": "Credenciais inválidas."}), 401

    except Exception as e:
        print(f"Erro durante o login: {e}")
        return jsonify({"error": "Erro interno do servidor."}), 500

    finally:
        conn.close()


if __name__ == '__main__':
    # O Replit roda automaticamente, mas é bom ter o if
    app.run(host='0.0.0.0', port=8080)

import os

import psycopg2
from flask import Flask, jsonify, request

# Importamos a classe Bcrypt para tipagem, mas a instância vem de gestor.py
from auth import auth_bp  # Importa o Blueprint de autenticação

# Importando Blueprints e conexões
from banco import banco_bp, get_db_connection
from gestor import (  # Importa o Blueprint do Gestor e a instância do Bcrypt
    bcrypt,
    gestor_bp,
)

app = Flask(__name__)

# 1. INICIALIZAÇÃO DO BCRYPT: Usamos a instância importada do gestor.py
# e a inicializamos com o app principal.
bcrypt.init_app(app) 
# A SESSION_SECRET DEVE SER LIDA DO AMBIENTE E SER LONGA E COMPLEXA!
app.config['SESSION_SECRET'] = os.getenv('SESSION_SECRET')


# REGISTRANDO BLUEPRINTS
app.register_blueprint(banco_bp)
app.register_blueprint(auth_bp)
app.register_blueprint(gestor_bp) # Rotas de /gestores, /login/gestor e /lojas


# --- ROTAS GERAIS E DE CLIENTE ---


@app.route('/', methods=['GET'])
def home():
    """Rota de boas-vindas para testar se a API está online."""
    return jsonify({
        "message": "API de E-commerce rodando!",
        "status": "online"
    })

# 8. Rota: Criar um novo Cliente (Cadastro) - MANTIDA AQUI
@app.route('/clientes', methods=['POST'])
def criar_cliente():
    """Cria um novo cliente, gerando o hash da senha."""
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

        conn.commit()
        cur.close()

        return jsonify({
            "message": "Cliente criado com sucesso",
            "cliente_id": cliente_id
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


# --- INÍCIO DO SERVIDOR FLASK ---
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)

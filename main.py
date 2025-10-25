import os

from flask import Flask, jsonify
from flask_cors import CORS

# Importamos a classe Bcrypt para tipagem, mas a instância vem de gestor.py
# Importando Blueprints e conexões
from banco import banco_bp
from cliente import cliente_bp
from gestor import (  # Importa o Blueprint do Gestor e a instância do Bcrypt
    bcrypt,
    gestor_bp,
)
from loja import loja_bp

app = Flask(__name__)
CORS(app, origins='*', supports_credentials=True) 

# 1. INICIALIZAÇÃO DO BCRYPT: Usamos a instância importada do gestor.py
# e a inicializamos com o app principal.
bcrypt.init_app(app) 
# A SESSION_SECRET DEVE SER LIDA DO AMBIENTE E SER LONGA E COMPLEXA!
app.config['SESSION_SECRET'] = os.getenv('SESSION_SECRET')


# REGISTRANDO BLUEPRINTS
app.register_blueprint(banco_bp)
app.register_blueprint(gestor_bp) # Rotas de /gestores, /login/gestor e /lojas
app.register_blueprint(loja_bp)
app.register_blueprint(cliente_bp)
# --- ROTAS GERAIS E DE CLIENTE ---


@app.route('/', methods=['GET'])
def home():
    """Rota de boas-vindas para testar se a API está online."""
    return jsonify({
        "message": "API de E-commerce rodando!",
        "status": "online"
    })




# --- INÍCIO DO SERVIDOR FLASK ---
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)

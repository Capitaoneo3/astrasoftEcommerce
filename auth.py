from functools import wraps

import jwt
from flask import Blueprint, current_app, g, jsonify, request

# Crie um Blueprint para modularizar funções de autenticação/utilitários.
# Embora o decorador não defina rotas, o Blueprint é um bom lugar para organizar
# futuras rotas de auth (como /auth/refresh-token) ou utilitários.
auth_bp = Blueprint('auth', __name__)

def token_obrigatorio(f):
    """
    Decorador que verifica a presença e validade de um token JWT no cabeçalho 
    Authorization (Bearer).

    Se válido, decodifica o payload e armazena 'gestor_id' e 'role' no objeto 'g'
    para que a rota protegida possa utilizá-los.
    """

    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        # Tenta extrair o token do cabeçalho 'Authorization: Bearer <token>'
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            if auth_header.startswith('Bearer '):
                token = auth_header.split(' ')[1]

        if not token:
            return jsonify({'message': 'Token de autenticação ausente!'}), 401

        try:
            # Acessa a chave secreta da configuração da aplicação principal
            session_secret = current_app.config.get('SESSION_SECRET')

            if not session_secret:
                 print("AVISO CRÍTICO: SESSION_SECRET não definida na configuração.")
                 return jsonify({'message': 'Erro de configuração do servidor.'}), 500

            # 1. Decodifica o token usando a chave secreta
            data = jwt.decode(token,
                              session_secret,
                              algorithms=["HS256"])
            # 2. Verifica a função do usuário
            role = data.get('role')

            # Mantendo a lógica original: só permite acesso a 'gestor'
            if role != 'gestor':
                return jsonify(
                    {'message':
                     'Acesso negado: Requer função de Gestor.'}), 403

            # Armazena o ID e a função no objeto 'g' para uso na rota
            g.user_id = data.get('gestor_id')
            g.user_role = role

        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token expirado.'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Token inválido.'}), 401
        except Exception as e:
            print(f"Erro na verificação do token: {e}")
            return jsonify({'message': 'Erro ao processar o token.'}), 500

        return f(*args, **kwargs)

    return decorated

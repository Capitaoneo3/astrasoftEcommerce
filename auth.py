# auth.py

from functools import wraps

import jwt
from flask import current_app, jsonify, request
from jwt import ExpiredSignatureError, InvalidSignatureError


# O decorador agora aceita o argumento role_necessaria
def token_obrigatorio(role_necessaria):
    """
    Decorador que verifica o token JWT.

    Aceita um argumento role_necessaria (ex: 'gestor' ou 'cliente') 
    e verifica se o 'role' no payload do token corresponde ao necessário.

    Passa o payload (dados_usuario) para a função decorada.
    """

    # A função decorador (a camada externa) recebe o role_necessaria
    def decorator(f):

        # A função interna (o wrapper) recebe os argumentos da rota
        @wraps(f)
        def decorated(*args, **kwargs):
            token = None
            auth_header = request.headers.get('Authorization')

            # 1. Obter o token
            if auth_header and auth_header.startswith('Bearer '):
                # Pega a parte do token, ignorando 'Bearer '
                token = auth_header.split(" ")[1]

            if not token:
                return jsonify({'error': 'Token de autenticação ausente.'}), 401

            try:
                # 2. Decodifica e valida o token
                session_secret = current_app.config.get('SESSION_SECRET')

                if not session_secret:
                    # Falha se a chave secreta não estiver configurada
                    raise Exception("SESSION_SECRET não configurado.")

                dados_usuario = jwt.decode(
                    token, 
                    session_secret, 
                    algorithms=["HS256"]
                )

                # 3. VERIFICAÇÃO DE PERFIL (ROLE)
                token_role = dados_usuario.get('role')
                if token_role != role_necessaria:
                     # Se o perfil no token não for o esperado para a rota
                     return jsonify({'error': f'Acesso negado. Necessário perfil: {role_necessaria}.'}), 403

            except ExpiredSignatureError:
                return jsonify({'error': 'Token expirado.'}), 401
            except InvalidSignatureError:
                return jsonify({'error': 'Token inválido.'}), 401
            except Exception as e:
                print(f"Erro ao processar token: {e}")
                return jsonify({'error': 'Erro interno do servidor ou token malformado.'}), 500

            # 4. Passa os dados do token (payload) para a função decorada
            return f(dados_usuario, *args, **kwargs)

        return decorated

    return decorator
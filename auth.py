from functools import wraps

import jwt
from flask import Blueprint, current_app, jsonify, request
from jwt import ExpiredSignatureError, InvalidSignatureError

# 1. Definição do Blueprint para rotas de autenticação
auth_bp = Blueprint('auth', __name__)

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


# Rota: Verificar Validade do Token (Gestor/Cliente)
@auth_bp.route('/token/verificar', methods=['POST'])
def verificar_token():
    """
    POST /token/verificar
    Verifica se um token JWT está ativo, expirado ou inválido.
    Aceita o token no cabeçalho Authorization ou no corpo JSON.
    Requer: Token JWT.
    Retorna: Status de validade (valid: true/false, expired: true/false).
    """
    # 1. Obter o token do cabeçalho Authorization (padrão)
    token = request.headers.get('Authorization')
    if token and token.startswith('Bearer '):
        token = token.split(' ')[1]

    # 2. Fallback: tentar obter do corpo JSON
    if not token and request.is_json:
        data = request.get_json()
        token = data.get('token')

    if not token:
        return jsonify({"valid": False, "expired": False, "message": "Token não fornecido."}), 400

    # 3. Tentar decodificar o token
    try:
        # A função jwt.decode, por padrão, verifica a expiração (exp)
        decoded = jwt.decode(token, current_app.config['SESSION_SECRET'], algorithms=['HS256'])

        # Token VÁLIDO
        return jsonify({
            "valid": True,
            "expired": False,
            "message": "Token JWT válido e ativo.",
            "user_id": decoded.get('gestor_id') or decoded.get('cliente_id'), # Retorna o ID que estiver presente
            "role": decoded.get('role')
        }), 200

    except jwt.ExpiredSignatureError:
        # Token EXPIRADO
        return jsonify({
            "valid": False,
            "expired": True,
            "message": "Token JWT expirado."
        }), 200 # OK 200 para checagem de status

    except jwt.InvalidTokenError as e:
        # Outros erros de token (assinatura inválida, formato errado, etc.)
        print(f"Erro de token: {e}")
        return jsonify({
            "valid": False,
            "expired": False,
            "message": "Token JWT inválido ou malformado."
        }), 401

    except Exception as e:
        print(f"Erro interno ao verificar token: {e}")
        return jsonify({
            "valid": False,
            "expired": False,
            "message": "Erro interno do servidor ao processar o token."
        }), 500

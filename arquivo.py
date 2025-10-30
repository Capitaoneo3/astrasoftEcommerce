import mimetypes  # Importação padrão do Python para determinar o Content-Type
from io import BytesIO

from flask import Blueprint, jsonify, send_file

# Assumindo que estas importações estão corretas no seu ambiente
from replit.object_storage import Client

# Criamos uma nova Blueprint para rotas de arquivos ou reutilizamos se já existir
# Vou criar uma nova aqui, mas você pode integrá-la à sua estrutura (ex: 'app_bp')
arquivo_bp = Blueprint('arquivo', __name__) 
client = Client()


# 📌 Rota 16 (Nova): Servir Arquivo do Data Storage (GET)
@arquivo_bp.route('/arquivo/<path:filename>', methods=['GET'])
# Esta rota deve ser pública para que os clientes (navegadores) possam carregar as imagens
def servir_arquivo(filename):
    """
    Busca um arquivo (imagem) no Replit Data Storage pelo seu nome e o envia ao cliente.
    O nome do arquivo é o 'path' do Data Storage (ex: 'loja_123_perfil.jpg').
    """

    try:
        # --- 1. Determinar o Content-Type (MIME Type) ---
        # Isso é crucial para que o navegador saiba como exibir o arquivo
        mimetype, _ = mimetypes.guess_type(filename)
        if not mimetype:
             # Fallback seguro para arquivos desconhecidos, ou você pode restringir
            mimetype = 'application/octet-stream' 

        # --- 2. Buscar o arquivo no Replit Data Storage ---
        # O método get_bytes() retorna o conteúdo binário do arquivo
        try:
            arquivo_bytes = client.download_as_bytes(filename)
        except KeyError:
            # O Data Storage lança KeyError se o arquivo não for encontrado
            return jsonify({"error": f"Arquivo '{filename}' não encontrado."}), 404
        except Exception as e:
            print(f"Erro ao acessar Data Storage: {e}")
            return jsonify({"error": "Falha ao acessar o Data Storage."}), 500

        # --- 3. Preparar o Conteúdo para Envio ---

        # Envolve o conteúdo binário em um objeto BytesIO
        buffer = BytesIO(arquivo_bytes)

        # --- 4. Enviar o Arquivo ao Cliente ---

        # send_file utiliza o buffer, determina o Content-Type e envia
        return send_file(
            buffer,
            mimetype=mimetype,
            as_attachment=False, # Define como 'inline' para visualização no navegador
            download_name=filename
        )

    except Exception as e:
        print(f"Erro interno ao servir arquivo: {e}")
        return jsonify({"error": f"Erro interno do servidor. Detalhe: {e}"}), 500

# --- Lembre-se de registrar esta Blueprint no seu app Flask principal ---
# Ex: app.register_blueprint(arquivo_bp)
import json
import os

import psycopg2
import psycopg2.errors
from flask import Blueprint, jsonify, request

# --- Assumindo estas importações corretas do seu ambiente ---
# Certifique-se de que 'auth', 'banco', e 'gestor' estejam acessíveis
from auth import token_obrigatorio
from banco import get_db_connection
from gestor import client  # Replit Object Storage Client

# Definição do Blueprint
produto_bp = Blueprint('produto', __name__)

# ==============================================================================
# 📌 Rota 11: Criar Produto (POST /produto)
# ==============================================================================
@produto_bp.route('/produto', methods=['POST'])
@token_obrigatorio(role_necessaria='gestor')
def criar_produto(dados_usuario):
    gestor_id_logado = dados_usuario.get('gestor_id')

    # 1. Captura e Validação Inicial dos dados
    loja_id_str = request.form.get('loja_id')
    nome_produto = request.form.get('nome_produto')
    valor_str = request.form.get('valor')
    estoque_str = request.form.get('estoque')

    descricao = request.form.get('descricao')
    valor_frete_str = request.form.get('valor_frete')

    foto_thumb = request.files.get('foto_thumb')
    lista_fotos_arquivos = request.files.getlist('lista_fotos')

    if not (loja_id_str and nome_produto and valor_str and estoque_str):
        return jsonify({
            "error": "Os campos 'loja_id', 'nome_produto', 'valor' e 'estoque' são obrigatórios."
        }), 400

    try:
        loja_id = int(loja_id_str)
        valor = float(valor_str)
        estoque = int(estoque_str)

        # Converte para float/None de forma segura
        valor_frete = float(valor_frete_str) if valor_frete_str else None

    except ValueError:
        return jsonify({"error": "Um ou mais campos numéricos estão inválidos."}), 400

    conn = get_db_connection()
    if conn is None:
        return jsonify({"error": "Falha na conexão com o banco de dados"}), 500

    caminho_foto_thumb = None
    caminhos_lista_fotos = []

    try:
        cur = conn.cursor()

        # 2. Validação: Propriedade da Loja
        cur.execute("SELECT gestor_id FROM lojas WHERE loja_id = %s;", (loja_id, ))
        resultado_loja = cur.fetchone()

        # ⚠️ Verificação: Se a loja_id não existir, resultado_loja será None
        if not resultado_loja:
            conn.rollback()
            return jsonify({"error": f"Loja com ID {loja_id} não encontrada."}), 404

        proprietario_id = resultado_loja[0]
        if proprietario_id != gestor_id_logado:
            conn.rollback()
            return jsonify({"error": "Acesso negado. Você só pode criar produtos para lojas que gerencia."}), 403

        # 3. Lógica de Upload de Imagens (mantida, pois está correta)
        if foto_thumb and foto_thumb.filename:
            extensao = os.path.splitext(foto_thumb.filename)[1]
            nome_arquivo = f"produto_{loja_id}_thumb_{os.urandom(4).hex()}{extensao}"
            client.upload_from_bytes(nome_arquivo, foto_thumb.read())
            caminho_foto_thumb = nome_arquivo

        for i, arquivo in enumerate(lista_fotos_arquivos):
            if arquivo and arquivo.filename:
                extensao = os.path.splitext(arquivo.filename)[1]
                nome_arquivo = f"produto_{loja_id}_foto_{i}_{os.urandom(4).hex()}{extensao}"
                client.upload_from_bytes(nome_arquivo, arquivo.read())
                caminhos_lista_fotos.append(nome_arquivo)

        lista_fotos_json = json.dumps(caminhos_lista_fotos)

        # 4. Execução do SQL INSERT
        query = """
        INSERT INTO produtos (
            loja_id, nome_produto, descricao, valor, valor_frete,
            foto_thumb, lista_fotos, estoque, data_cadastro
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP)
        RETURNING produto_id;
        """
        valores = (
            loja_id, nome_produto, descricao, valor, valor_frete,
            caminho_foto_thumb, lista_fotos_json, estoque,
        )

        cur.execute(query, valores)
        produto_id_result = cur.fetchone()

        # ⚠️ Verificação: Garante que o fetchone retornou um ID
        if not produto_id_result:
            raise Exception("Falha ao recuperar produto_id após INSERT.")

        produto_id = produto_id_result[0]
        conn.commit()

        return jsonify({
            "message": f"Produto '{nome_produto}' criado com sucesso.",
            "produto_id": produto_id,
            "foto_thumb": caminho_foto_thumb,
            "lista_fotos_caminhos": caminhos_lista_fotos
        }), 201

    except psycopg2.Error as e:
        conn.rollback()
        print(f"Erro de Banco de Dados ao criar produto: {e}")
        mensagem_erro = f"Erro no banco de dados: {e.pgerror.strip()}" if e.pgerror else "Erro de integridade no banco de dados."
        return jsonify({"error": mensagem_erro}), 400
    except Exception as e:
        conn.rollback()
        print(f"Erro geral ao criar produto: {e}")
        return jsonify({"error": f"Erro interno ao criar produto. Detalhe: {e}"}), 500
    finally:
        if conn:
            conn.close()

# ==============================================================================
# 📌 Rota 12: Atualizar Produto (PUT /produto/<int:produto_id>)
# ==============================================================================
@produto_bp.route('/produto/<int:produto_id>', methods=['PUT'])
@token_obrigatorio(role_necessaria='gestor')
def atualizar_produto(dados_usuario, produto_id):
    gestor_id_logado = dados_usuario.get('gestor_id')

    # 1. Captura e Montagem dos Updates (ajustado para usar variáveis com _str)
    nome_produto = request.form.get('nome_produto')
    descricao = request.form.get('descricao')
    valor_str = request.form.get('valor')
    valor_frete_str = request.form.get('valor_frete')
    estoque_str = request.form.get('estoque')

    foto_thumb_arquivo = request.files.get('foto_thumb')
    lista_fotos_arquivos = request.files.getlist('lista_fotos')

    updates = []
    valores = []

    # Processamento de campos textuais/numéricos
    if nome_produto:
        updates.append("nome_produto = %s")
        valores.append(nome_produto)
    if descricao is not None:
        updates.append("descricao = %s")
        valores.append(descricao)

    try:
        if valor_str is not None:
            valor_tratado = float(valor_str) if valor_str else None
            updates.append("valor = %s")
            valores.append(valor_tratado)
        if valor_frete_str is not None:
            valor_frete_tratado = float(valor_frete_str) if valor_frete_str else None
            updates.append("valor_frete = %s")
            valores.append(valor_frete_tratado)
        if estoque_str is not None:
            estoque_tratado = int(estoque_str) if estoque_str else None
            updates.append("estoque = %s")
            valores.append(estoque_tratado)
    except ValueError:
        return jsonify({"error": "Os campos 'valor', 'valor_frete' e 'estoque' devem ser números válidos."}), 400

    if not updates and not foto_thumb_arquivo and not lista_fotos_arquivos:
        return jsonify({"error": "Nenhum dado ou arquivo fornecido para atualização."}), 400

    conn = get_db_connection()
    if conn is None:
        return jsonify({"error": "Falha na conexão com o banco de dados"}), 500

    try:
        cur = conn.cursor()

        # 2. Busca inicial: Propriedade e Dados Antigos
        cur.execute(
            """
            SELECT p.foto_thumb, p.lista_fotos, l.gestor_id 
            FROM produtos p JOIN lojas l ON p.loja_id = l.loja_id
            WHERE p.produto_id = %s;
            """, (produto_id, ))
        resultado_produto = cur.fetchone()

        # ⚠️ Verificação de None
        if not resultado_produto:
            conn.rollback()
            return jsonify({"error": f"Produto com ID {produto_id} não encontrado."}), 404

        foto_thumb_antiga, lista_fotos_json_antiga, proprietario_id = resultado_produto

        # 2.1. Validação de Propriedade
        if proprietario_id != gestor_id_logado:
            conn.rollback()
            return jsonify({"error": "Acesso negado. Você só pode atualizar produtos das lojas que gerencia."}), 403

        # 3. Lógica de Upload/Substituição de Fotos (mantida, pois está correta)
        if foto_thumb_arquivo and foto_thumb_arquivo.filename:
            if foto_thumb_antiga:
                client.delete(foto_thumb_antiga, ignore_not_found=True)

            extensao = os.path.splitext(foto_thumb_arquivo.filename)[1]
            nome_arquivo = f"produto_{produto_id}_thumb_{os.urandom(4).hex()}{extensao}"
            client.upload_from_bytes(nome_arquivo, foto_thumb_arquivo.read())

            updates.append("foto_thumb = %s")
            valores.append(nome_arquivo)

        if lista_fotos_arquivos and any(f.filename for f in lista_fotos_arquivos):
            if lista_fotos_json_antiga:
                caminhos_antigos = json.loads(lista_fotos_json_antiga)
                for caminho in caminhos_antigos:
                    client.delete(caminho, ignore_not_found=True)

            caminhos_lista_fotos = []
            for i, arquivo in enumerate(lista_fotos_arquivos):
                if arquivo and arquivo.filename:
                    extensao = os.path.splitext(arquivo.filename)[1]
                    nome_arquivo = f"produto_{produto_id}_foto_{i}_{os.urandom(4).hex()}{extensao}"
                    client.upload_from_bytes(nome_arquivo, arquivo.read())
                    caminhos_lista_fotos.append(nome_arquivo)

            lista_fotos_json_nova = json.dumps(caminhos_lista_fotos)
            updates.append("lista_fotos = %s")
            valores.append(lista_fotos_json_nova)

        # 4. Execução do SQL UPDATE
        if updates:
            query = f"""
            UPDATE produtos
            SET {', '.join(updates)}, data_atualizacao = CURRENT_TIMESTAMP
            WHERE produto_id = %s;
            """
            valores.append(produto_id)

            cur.execute(query, tuple(valores))
            conn.commit()
            cur.close()

            return jsonify({"message": f"Produto (ID: {produto_id}) atualizado com sucesso."}), 200

    except Exception as e:
        conn.rollback()
        print(f"Erro ao atualizar produto {produto_id}: {e}")
        return jsonify({"error": f"Erro interno ao atualizar produto. Detalhe: {e}"}), 500

    finally:
        if conn:
            conn.close()

# ==============================================================================
# 📌 Rota 13: Listar/Buscar Produtos (GET /produto) - Ajustado para ser '/produto'
# ==============================================================================
@produto_bp.route('/produto', methods=['GET'])
def listar_produtos():
    conn = get_db_connection()
    if conn is None:
        return jsonify({"error": "Falha na conexão com o banco de dados"}), 500

    try:
        cur = conn.cursor()

        # 1. Captura de Parâmetros (Uso seguro de type=int/float nos argumentos)
        q = request.args.get('q', '').strip()
        loja_id = request.args.get('loja_id', type=int)
        min_valor = request.args.get('min_valor', type=float)
        max_valor = request.args.get('max_valor', type=float)

        ordem_por = request.args.get('ordem_por', 'data_cadastro')
        direcao = request.args.get('direcao', 'DESC').upper()

        limite = request.args.get('limite', 10, type=int)
        pagina = request.args.get('pagina', 1, type=int)
        offset = (pagina - 1) * limite

        # ... (O restante da lógica de listagem foi mantida, pois está robusta)

        # 2. Montagem da Cláusula WHERE
        condicoes = []
        valores = []

        if q:
            condicoes.append("(p.nome_produto ILIKE %s OR p.descricao ILIKE %s)")
            valores.append(f"%{q}%")
            valores.append(f"%{q}%")

        if loja_id is not None:
            condicoes.append("p.loja_id = %s")
            valores.append(loja_id)

        if min_valor is not None:
            condicoes.append("p.valor >= %s")
            valores.append(min_valor)

        if max_valor is not None:
            condicoes.append("p.valor <= %s")
            valores.append(max_valor)

        where_clause = "WHERE " + " AND ".join(condicoes) if condicoes else ""

        # 3. Validação e Montagem da Ordenação
        colunas_permitidas = {
            'nome_produto', 'valor', 'data_cadastro', 'estoque', 'loja_id'
        }
        if ordem_por not in colunas_permitidas:
            ordem_por = 'data_cadastro'
        if direcao not in ('ASC', 'DESC'):
            direcao = 'DESC'

        order_clause = f"ORDER BY p.{ordem_por} {direcao}"

        # 4. Contagem Total
        cur.execute(f"SELECT COUNT(p.produto_id) FROM produtos p {where_clause};", tuple(valores))
        total_produtos_result = cur.fetchone()
        # ⚠️ Verificação de None (embora o COUNT dificilmente seja None)
        total_produtos = total_produtos_result[0] if total_produtos_result else 0 

        # 5. Query Principal
        query_principal = f"""
            SELECT 
                p.produto_id, p.nome_produto, p.descricao, p.valor, p.valor_frete, 
                p.estoque, p.data_cadastro, p.foto_thumb, p.lista_fotos,
                l.loja_id, l.nome_loja
            FROM produtos p JOIN lojas l ON p.loja_id = l.loja_id
            {where_clause} {order_clause}
            LIMIT %s OFFSET %s;
        """
        valores_principal = valores + [limite, offset]
        cur.execute(query_principal, tuple(valores_principal))
        produtos_db = cur.fetchall()

        # 6. Formatação e Deserialização
        colunas = [
            'produto_id', 'nome_produto', 'descricao', 'valor', 'valor_frete', 
            'estoque', 'data_cadastro', 'foto_thumb', 'lista_fotos', 'loja_id', 'nome_loja'
        ]

        lista_produtos_formatada = []
        for produto in produtos_db:
            produto_dict = dict(zip(colunas, produto))
            if produto_dict['lista_fotos']:
                try:
                    produto_dict['lista_fotos'] = json.loads(produto_dict['lista_fotos'])
                except json.JSONDecodeError:
                    produto_dict['lista_fotos'] = []
            else:
                 produto_dict['lista_fotos'] = []
            lista_produtos_formatada.append(produto_dict)

        # 7. Estrutura da Resposta
        resposta = {
            "produtos": lista_produtos_formatada,
            "meta": {
                "total_produtos": total_produtos, "limite": limite, "pagina_atual": pagina,
                "total_paginas": (total_produtos + limite - 1) // limite,
                "filtros_aplicados": {"q": q, "loja_id": loja_id, "min_valor": min_valor, "max_valor": max_valor}
            }
        }

        return jsonify(resposta), 200

    except psycopg2.Error as e:
        conn.rollback()
        print(f"Erro no banco de dados ao listar produtos: {e}")
        return jsonify({"error": f"Erro de banco de dados: {e}"}), 500
    except Exception as e:
        print(f"Erro interno ao listar produtos: {e}")
        return jsonify({"error": f"Erro interno do servidor. Detalhe: {e}"}), 500
    finally:
        if conn:
            conn.close()

# ==============================================================================
# 📌 Rota 14: Detalhe do Produto (GET /produto/<int:produto_id>)
# ==============================================================================
@produto_bp.route('/produto/<int:produto_id>', methods=['GET'])
def detalhe_produto(produto_id):
    conn = get_db_connection()
    if conn is None:
        return jsonify({"error": "Falha na conexão com o banco de dados"}), 500

    try:
        cur = conn.cursor()

        query_principal = """
            SELECT 
                p.produto_id, p.nome_produto, p.descricao, p.valor, p.valor_frete, 
                p.estoque, p.data_cadastro, p.foto_thumb, p.lista_fotos,
                l.loja_id, l.nome_loja
            FROM produtos p JOIN lojas l ON p.loja_id = l.loja_id
            WHERE p.produto_id = %s;
        """
        cur.execute(query_principal, (produto_id,))
        produto_db = cur.fetchone()

        # ⚠️ Verificação de None
        if not produto_db:
            return jsonify({"error": f"Produto com ID {produto_id} não encontrado."}), 404

        colunas = [
            'produto_id', 'nome_produto', 'descricao', 'valor', 'valor_frete', 
            'estoque', 'data_cadastro', 'foto_thumb', 'lista_fotos', 'loja_id', 'nome_loja'
        ]
        produto_formatado = dict(zip(colunas, produto_db))

        # Deserialização
        if produto_formatado.get('lista_fotos'):
            try:
                produto_formatado['lista_fotos'] = json.loads(produto_formatado['lista_fotos'])
            except json.JSONDecodeError:
                produto_formatado['lista_fotos'] = []
        else:
             produto_formatado['lista_fotos'] = []

        return jsonify(produto_formatado), 200

    except psycopg2.Error as e:
        print(f"Erro no banco de dados ao buscar produto {produto_id}: {e}")
        return jsonify({"error": f"Erro de banco de dados: {e}"}), 500
    except Exception as e:
        print(f"Erro interno ao buscar produto {produto_id}: {e}")
        return jsonify({"error": f"Erro interno do servidor. Detalhe: {e}"}), 500
    finally:
        if conn:
            conn.close()

# ==============================================================================
# 📌 Rota 15: Deletar Produto (DELETE /produto/<int:produto_id>)
# ==============================================================================
@produto_bp.route('/produto/<int:produto_id>', methods=['DELETE'])
@token_obrigatorio(role_necessaria='gestor')
def deletar_produto(dados_usuario, produto_id):
    gestor_id_logado = dados_usuario.get('gestor_id')

    conn = get_db_connection()
    if conn is None:
        return jsonify({"error": "Falha na conexão com o banco de dados"}), 500

    try:
        cur = conn.cursor()

        # 1. Busca Inicial: Propriedade e Caminhos de Arquivo
        cur.execute(
            """
            SELECT p.foto_thumb, p.lista_fotos, l.gestor_id 
            FROM produtos p JOIN lojas l ON p.loja_id = l.loja_id
            WHERE p.produto_id = %s;
            """, (produto_id, ))
        resultado_produto = cur.fetchone()

        # ⚠️ Verificação de None
        if not resultado_produto:
            conn.rollback()
            return jsonify({"error": f"Produto com ID {produto_id} não encontrado."}), 404

        foto_thumb_caminho, lista_fotos_json, proprietario_id = resultado_produto

        # 1.1. Validação de Propriedade
        if proprietario_id != gestor_id_logado:
            conn.rollback()
            return jsonify({
                "error": "Acesso negado. Você só pode deletar produtos das lojas que gerencia."
            }), 403

        # 2. Deletar Arquivos do Data Storage (mantida, pois está correta)
        arquivos_a_deletar = []
        if foto_thumb_caminho:
            arquivos_a_deletar.append(foto_thumb_caminho)
        if lista_fotos_json:
            try:
                caminhos_lista = json.loads(lista_fotos_json)
                arquivos_a_deletar.extend(caminhos_lista)
            except json.JSONDecodeError:
                pass

        if arquivos_a_deletar:
            for arquivo in arquivos_a_deletar:
                try:
                    client.delete(arquivo, ignore_not_found=True)
                except Exception as e:
                    print(f"Aviso: Falha ao deletar arquivo {arquivo} do Data Storage: {e}")

        # 3. Deletar o Produto do Banco de Dados
        cur.execute("DELETE FROM produtos WHERE produto_id = %s;", (produto_id, ))
        conn.commit()
        cur.close()

        return jsonify({"message": f"Produto (ID: {produto_id}) e seus arquivos associados deletados com sucesso."}), 200

    except Exception as e:
        conn.rollback()
        print(f"Erro fatal ao deletar produto {produto_id}: {e}")
        return jsonify({"error": f"Erro interno ao deletar produto. Detalhe: {e}"}), 500

    finally:
        if conn:
            conn.close()
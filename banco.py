import os

import psycopg2
from flask import Blueprint, jsonify

banco_bp = Blueprint('banco', __name__)


def get_db_connection():
  db_host = os.getenv("DB_HOST")
  db_port = os.getenv("DB_PORT")
  db_name = os.getenv("DB_NAME")
  db_user = os.getenv("DB_USER")
  db_pass = os.getenv("DB_PASS")

  try:
    conn = psycopg2.connect(
        user=db_user,
        password=db_pass,
        host=db_host,
        port=db_port,
        dbname=db_name,
    )
    print("VARIÁVEIS Lidas do AMBIENTE (Secrets/OS) - Conexão OK.")
    print(f"DB_HOST: {db_host}")
    print(f"DB_PORT: {db_port}")
    print(f"DB_NAME: {db_name}")
    print(f"DB_USER: {db_user}")
    return conn
  except Exception as e:
    print("=" * 80)
    print("!!!! FALHA CRÍTICA NA CONEXÃO COM O BANCO DE DADOS !!!!")
    print(f"Mensagem de erro do psycopg2: {e}")
    print("-" * 80)
    print("VARIÁVEIS Lidas do AMBIENTE (Secrets/OS):")
    print(f"DB_HOST: {db_host}")
    print(f"DB_PORT: {db_port}")
    print(f"DB_NAME: {db_name}")
    print(f"DB_USER: {db_user}")
    print(
        f"DB_PASS: {'*** LIDO COM SUCESSO ***' if db_pass else '!!! AUSENTE/VAZIO !!!'}"
    )
    print(
        f"SESSION_SECRET: {'*** LIDO ***' if os.getenv('SESSION_SECRET') else '!!! AUSENTE/VAZIO !!!'}"
    )
    print("=" * 80)
    return None


@banco_bp.route('/db-status', methods=['GET'])
def db_status():
  """Verifica a conectividade básica com o banco de dados."""
  conn = get_db_connection()
  if conn is None:
    return jsonify({
        "db_status":
        "offline",
        "message":
        "Falha na conexão. Verifique o log do console para os valores lidos."
    }), 500
  try:
    # Tenta executar uma consulta trivial para confirmar que o banco está vivo
    cur = conn.cursor()
    cur.execute("SELECT 1;")
    cur.close()
    return jsonify({
        "db_status":
        "online",
        "message":
        "Conexão com o PostgreSQL estabelecida com sucesso."
    }), 200
  except Exception as e:
    print(f"Erro ao testar consulta no DB: {e}")
    return jsonify({
        "db_status": "error",
        "message": f"Conexão OK, mas erro na consulta. Erro: {e}"
    }), 500
  finally:
    if conn:
      conn.close()

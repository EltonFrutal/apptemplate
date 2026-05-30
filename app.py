from flask import Flask, render_template, request, jsonify, session, redirect, url_for
import psycopg2
import psycopg2.extras
import bcrypt
from functools import wraps

app = Flask(__name__)
app.secret_key = 'apptemplate_secret_2024'

# ================================================
# CONEXÃO COM O BANCO
# ================================================
def get_db():
    return psycopg2.connect(
        host="localhost",
        database="db_apptemplate",
        user="postgres",
        password="95668Elton",
        port="5432"
    )

def query(sql, params=None, fetch='all'):
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(sql, params or ())
    if fetch == 'all':
        result = cur.fetchall()
    elif fetch == 'one':
        result = cur.fetchone()
    else:
        result = None
    conn.commit()
    cur.close()
    conn.close()
    return result

def execute(sql, params=None):
    conn = get_db()
    cur = conn.cursor()
    cur.execute(sql, params or ())
    conn.commit()
    cur.close()
    conn.close()

# ================================================
# AUTENTICAÇÃO
# ================================================
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'usuario_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'usuario_id' not in session:
            return redirect(url_for('login'))
        if not session.get('is_admin'):
            return jsonify({'erro': 'Acesso negado'}), 403
        return f(*args, **kwargs)
    return decorated

# ================================================
# LOGIN / LOGOUT
# ================================================
@app.route('/', methods=['GET', 'POST'])
def login():
    if 'usuario_id' in session:
        return redirect(url_for('dashboard'))

    erro = None
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        senha = request.form.get('senha', '')

        usuario = query(
            "SELECT * FROM usuarios WHERE email = %s AND ativo = true",
            (email,), fetch='one'
        )

        if usuario and bcrypt.checkpw(senha.encode(), usuario['senha_hash'].encode()):
            session['usuario_id'] = str(usuario['id'])
            session['nome']       = usuario['nome']
            session['email']      = usuario['email']
            session['is_admin']   = usuario['is_admin']
            session['foto_url']   = usuario.get('foto_url')

            execute("UPDATE usuarios SET ultimo_acesso = now() WHERE id = %s", (usuario['id'],))
            return redirect(url_for('dashboard'))
        else:
            erro = 'Email ou senha incorretos'

    return render_template('login.html', erro=erro)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# ================================================
# DASHBOARD
# ================================================
@app.route('/dashboard')
@login_required
def dashboard():
    total_usuarios  = query("SELECT COUNT(*) as t FROM usuarios WHERE ativo=true",  fetch='one')['t']
    total_empresas  = query("SELECT COUNT(*) as t FROM empresas WHERE ativo=true",  fetch='one')['t']
    total_filiais   = query("SELECT COUNT(*) as t FROM filiais  WHERE ativo=true",  fetch='one')['t']
    total_modulos   = query("SELECT COUNT(*) as t FROM modulos  WHERE ativo=true",  fetch='one')['t']
    return render_template('dashboard.html',
        total_usuarios=total_usuarios,
        total_empresas=total_empresas,
        total_filiais=total_filiais,
        total_modulos=total_modulos
    )

# ================================================
# USUÁRIOS
# ================================================
@app.route('/usuarios')
@login_required
def usuarios():
    return render_template('usuarios.html')

@app.route('/api/usuarios', methods=['GET'])
@login_required
def api_usuarios_list():
    rows = query("""
        SELECT id, email, nome, telefone, is_admin, ativo,
               foto_url, ultimo_acesso, criado_em
        FROM usuarios ORDER BY nome
    """)
    return jsonify([dict(r) for r in rows])

@app.route('/api/usuarios', methods=['POST'])
@login_required
def api_usuarios_create():
    d = request.json
    if not d.get('email') or not d.get('nome') or not d.get('senha'):
        return jsonify({'erro': 'Email, nome e senha são obrigatórios'}), 400
    senha_hash = bcrypt.hashpw(d['senha'].encode(), bcrypt.gensalt(12)).decode()
    try:
        execute("""
            INSERT INTO usuarios (email, nome, senha_hash, telefone, is_admin, ativo, criado_por)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, (d['email'].lower(), d['nome'], senha_hash,
              d.get('telefone'), d.get('is_admin', False),
              d.get('ativo', True), session['usuario_id']))
        return jsonify({'ok': True})
    except Exception as e:
        return jsonify({'erro': str(e)}), 400

@app.route('/api/usuarios/<uid>', methods=['PUT'])
@login_required
def api_usuarios_update(uid):
    d = request.json
    if d.get('senha'):
        senha_hash = bcrypt.hashpw(d['senha'].encode(), bcrypt.gensalt(12)).decode()
        execute("""
            UPDATE usuarios SET nome=%s, email=%s, telefone=%s,
            is_admin=%s, ativo=%s, senha_hash=%s,
            alterado_em=now(), alterado_por=%s WHERE id=%s
        """, (d['nome'], d['email'].lower(), d.get('telefone'),
              d.get('is_admin', False), d.get('ativo', True),
              senha_hash, session['usuario_id'], uid))
    else:
        execute("""
            UPDATE usuarios SET nome=%s, email=%s, telefone=%s,
            is_admin=%s, ativo=%s,
            alterado_em=now(), alterado_por=%s WHERE id=%s
        """, (d['nome'], d['email'].lower(), d.get('telefone'),
              d.get('is_admin', False), d.get('ativo', True),
              session['usuario_id'], uid))
    return jsonify({'ok': True})

@app.route('/api/usuarios/<uid>', methods=['DELETE'])
@admin_required
def api_usuarios_delete(uid):
    if uid == session['usuario_id']:
        return jsonify({'erro': 'Não é possível excluir o próprio usuário'}), 400
    execute("UPDATE usuarios SET ativo=false, alterado_em=now() WHERE id=%s", (uid,))
    return jsonify({'ok': True})

# ================================================
# EMPRESAS
# ================================================
@app.route('/empresas')
@login_required
def empresas():
    return render_template('empresas.html')

@app.route('/api/empresas', methods=['GET'])
@login_required
def api_empresas_list():
    rows = query("""
        SELECT e.*,
               COUNT(f.id) as total_filiais
        FROM empresas e
        LEFT JOIN filiais f ON f.empresa_id = e.id AND f.ativo = true
        GROUP BY e.id ORDER BY e.razao_social
    """)
    return jsonify([dict(r) for r in rows])

@app.route('/api/empresas', methods=['POST'])
@login_required
def api_empresas_create():
    d = request.json
    if not d.get('codigo') or not d.get('razao_social'):
        return jsonify({'erro': 'Código e razão social são obrigatórios'}), 400
    try:
        execute("""
            INSERT INTO empresas (codigo, codigo_consys, razao_social, nome_fantasia,
                                  cnpj, email, telefone, ativo, criado_por)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (d['codigo'], d.get('codigo_consys'), d['razao_social'],
              d.get('nome_fantasia'), d.get('cnpj'), d.get('email'),
              d.get('telefone'), d.get('ativo', True), session['usuario_id']))
        return jsonify({'ok': True})
    except Exception as e:
        return jsonify({'erro': str(e)}), 400

@app.route('/api/empresas/<eid>', methods=['PUT'])
@login_required
def api_empresas_update(eid):
    d = request.json
    execute("""
        UPDATE empresas SET codigo=%s, codigo_consys=%s, razao_social=%s,
        nome_fantasia=%s, cnpj=%s, email=%s, telefone=%s, ativo=%s,
        alterado_em=now(), alterado_por=%s WHERE id=%s
    """, (d['codigo'], d.get('codigo_consys'), d['razao_social'],
          d.get('nome_fantasia'), d.get('cnpj'), d.get('email'),
          d.get('telefone'), d.get('ativo', True),
          session['usuario_id'], eid))
    return jsonify({'ok': True})

@app.route('/api/empresas/<eid>', methods=['DELETE'])
@admin_required
def api_empresas_delete(eid):
    execute("UPDATE empresas SET ativo=false, alterado_em=now() WHERE id=%s", (eid,))
    return jsonify({'ok': True})

# ================================================
# FILIAIS
# ================================================
@app.route('/filiais')
@login_required
def filiais():
    empresas_list = query("SELECT id, razao_social, nome_fantasia FROM empresas WHERE ativo=true ORDER BY razao_social")
    return render_template('filiais.html', empresas=empresas_list)

@app.route('/api/filiais', methods=['GET'])
@login_required
def api_filiais_list():
    empresa_id = request.args.get('empresa_id')
    if empresa_id:
        rows = query("""
            SELECT f.*, e.nome_fantasia as empresa_nome
            FROM filiais f
            JOIN empresas e ON e.id = f.empresa_id
            WHERE f.empresa_id = %s ORDER BY f.is_matriz DESC, f.nome
        """, (empresa_id,))
    else:
        rows = query("""
            SELECT f.*, e.nome_fantasia as empresa_nome
            FROM filiais f
            JOIN empresas e ON e.id = f.empresa_id
            ORDER BY e.razao_social, f.is_matriz DESC, f.nome
        """)
    return jsonify([dict(r) for r in rows])

@app.route('/api/filiais', methods=['POST'])
@login_required
def api_filiais_create():
    d = request.json
    if not d.get('empresa_id') or not d.get('nome'):
        return jsonify({'erro': 'Empresa e nome são obrigatórios'}), 400
    try:
        execute("""
            INSERT INTO filiais (empresa_id, nome, codigo, codigo_consys,
                                 cnpj, endereco, cidade, estado, is_matriz, ativo, criado_por)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (d['empresa_id'], d['nome'], d.get('codigo'), d.get('codigo_consys'),
              d.get('cnpj'), d.get('endereco'), d.get('cidade'), d.get('estado'),
              d.get('is_matriz', False), d.get('ativo', True), session['usuario_id']))
        return jsonify({'ok': True})
    except Exception as e:
        return jsonify({'erro': str(e)}), 400

@app.route('/api/filiais/<fid>', methods=['PUT'])
@login_required
def api_filiais_update(fid):
    d = request.json
    execute("""
        UPDATE filiais SET nome=%s, codigo=%s, codigo_consys=%s, cnpj=%s,
        endereco=%s, cidade=%s, estado=%s, is_matriz=%s, ativo=%s,
        alterado_em=now(), alterado_por=%s WHERE id=%s
    """, (d['nome'], d.get('codigo'), d.get('codigo_consys'), d.get('cnpj'),
          d.get('endereco'), d.get('cidade'), d.get('estado'),
          d.get('is_matriz', False), d.get('ativo', True),
          session['usuario_id'], fid))
    return jsonify({'ok': True})

@app.route('/api/filiais/<fid>', methods=['DELETE'])
@admin_required
def api_filiais_delete(fid):
    execute("UPDATE filiais SET ativo=false, alterado_em=now() WHERE id=%s", (fid,))
    return jsonify({'ok': True})

# ================================================
# MÓDULOS
# ================================================
@app.route('/modulos')
@login_required
def modulos():
    apps_list = query("SELECT id, codigo, nome FROM apps WHERE ativo=true ORDER BY nome")
    return render_template('modulos.html', apps=apps_list)

@app.route('/api/modulos', methods=['GET'])
@login_required
def api_modulos_list():
    rows = query("""
        SELECT m.*, a.nome as app_nome
        FROM modulos m
        JOIN apps a ON a.id = m.app_id
        ORDER BY a.nome, m.ordem, m.nome
    """)
    return jsonify([dict(r) for r in rows])

@app.route('/api/modulos', methods=['POST'])
@login_required
def api_modulos_create():
    d = request.json
    if not d.get('app_id') or not d.get('codigo') or not d.get('nome'):
        return jsonify({'erro': 'App, código e nome são obrigatórios'}), 400
    try:
        execute("""
            INSERT INTO modulos (app_id, codigo, nome, icone, url_rota, ordem, ativo, criado_por)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """, (d['app_id'], d['codigo'], d['nome'], d.get('icone'),
              d.get('url_rota'), d.get('ordem', 0),
              d.get('ativo', True), session['usuario_id']))
        return jsonify({'ok': True})
    except Exception as e:
        return jsonify({'erro': str(e)}), 400

@app.route('/api/modulos/<mid>', methods=['PUT'])
@login_required
def api_modulos_update(mid):
    d = request.json
    execute("""
        UPDATE modulos SET nome=%s, codigo=%s, icone=%s, url_rota=%s,
        ordem=%s, ativo=%s, alterado_em=now(), alterado_por=%s WHERE id=%s
    """, (d['nome'], d['codigo'], d.get('icone'), d.get('url_rota'),
          d.get('ordem', 0), d.get('ativo', True),
          session['usuario_id'], mid))
    return jsonify({'ok': True})

@app.route('/api/modulos/<mid>', methods=['DELETE'])
@admin_required
def api_modulos_delete(mid):
    execute("UPDATE modulos SET ativo=false, alterado_em=now() WHERE id=%s", (mid,))
    return jsonify({'ok': True})

# ================================================
# PERMISSÕES
# ================================================
@app.route('/permissoes')
@login_required
def permissoes():
    usuarios_list = query("SELECT id, nome, email FROM usuarios WHERE ativo=true ORDER BY nome")
    apps_list     = query("SELECT id, codigo, nome FROM apps WHERE ativo=true ORDER BY nome")
    empresas_list = query("SELECT id, codigo, razao_social, nome_fantasia FROM empresas WHERE ativo=true ORDER BY razao_social")
    return render_template('permissoes.html',
        usuarios=usuarios_list, apps=apps_list, empresas=empresas_list)

@app.route('/api/permissoes', methods=['GET'])
@login_required
def api_permissoes_list():
    rows = query("""
        SELECT p.*,
               u.nome  as usuario_nome, u.email as usuario_email,
               a.nome  as app_nome,
               e.nome_fantasia as empresa_nome,
               f.nome  as filial_nome,
               m.nome  as modulo_nome
        FROM permissoes p
        JOIN usuarios u ON u.id = p.usuario_id
        JOIN apps     a ON a.id = p.app_id
        JOIN empresas e ON e.id = p.empresa_id
        LEFT JOIN filiais f ON f.id = p.filial_id
        LEFT JOIN modulos m ON m.id = p.modulo_id
        ORDER BY u.nome, a.nome, e.nome_fantasia
    """)
    return jsonify([dict(r) for r in rows])

@app.route('/api/permissoes/filiais/<empresa_id>', methods=['GET'])
@login_required
def api_permissoes_filiais(empresa_id):
    rows = query("SELECT id, nome FROM filiais WHERE empresa_id=%s AND ativo=true ORDER BY is_matriz DESC, nome", (empresa_id,))
    return jsonify([dict(r) for r in rows])

@app.route('/api/permissoes/modulos/<app_id>', methods=['GET'])
@login_required
def api_permissoes_modulos(app_id):
    rows = query("SELECT id, nome FROM modulos WHERE app_id=%s AND ativo=true ORDER BY ordem, nome", (app_id,))
    return jsonify([dict(r) for r in rows])

@app.route('/api/permissoes', methods=['POST'])
@login_required
def api_permissoes_create():
    d = request.json
    if not d.get('usuario_id') or not d.get('app_id') or not d.get('empresa_id'):
        return jsonify({'erro': 'Usuário, app e empresa são obrigatórios'}), 400
    try:
        execute("""
            INSERT INTO permissoes
              (usuario_id, app_id, empresa_id, filial_id, modulo_id,
               perfil, pode_incluir, pode_alterar, pode_excluir, pode_exportar, criado_por)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        """, (d['usuario_id'], d['app_id'], d['empresa_id'],
              d.get('filial_id') or None, d.get('modulo_id') or None,
              d.get('perfil','view'),
              d.get('pode_incluir', False), d.get('pode_alterar', False),
              d.get('pode_excluir', False), d.get('pode_exportar', False),
              session['usuario_id']))
        return jsonify({'ok': True})
    except Exception as e:
        return jsonify({'erro': str(e)}), 400

@app.route('/api/permissoes/<pid>', methods=['PUT'])
@login_required
def api_permissoes_update(pid):
    d = request.json
    execute("""
        UPDATE permissoes SET perfil=%s,
        pode_incluir=%s, pode_alterar=%s, pode_excluir=%s, pode_exportar=%s,
        filial_id=%s, modulo_id=%s,
        alterado_em=now(), alterado_por=%s WHERE id=%s
    """, (d.get('perfil','view'),
          d.get('pode_incluir', False), d.get('pode_alterar', False),
          d.get('pode_excluir', False), d.get('pode_exportar', False),
          d.get('filial_id') or None, d.get('modulo_id') or None,
          session['usuario_id'], pid))
    return jsonify({'ok': True})

@app.route('/api/permissoes/<pid>', methods=['DELETE'])
@admin_required
def api_permissoes_delete(pid):
    execute("DELETE FROM permissoes WHERE id=%s", (pid,))
    return jsonify({'ok': True})

# ================================================
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)

# -*- coding: utf-8 -*-

import os
# --- SOLUCAO DEFINITIVA PARA ENCODING (CAMADA 1) ---
# Forca o Python e o driver do PostgreSQL a usarem UTF-8 no ambiente.
os.environ['PGCLIENTENCODING'] = 'UTF8'
os.environ['PYTHONIOENCODING'] = 'utf-8'

import json
import psycopg2
import psycopg2.extras
import pandas as pd
from datetime import datetime, timedelta
import pytz
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, send_file
from functools import wraps
import io
import math
import secrets

# --- CONFIGURACAO INICIAL DO APP ---
app = Flask(__name__)
app.secret_key = 'chave-secreta-muito-forte-para-producao-v17-final'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['LEADS_PER_PAGE'] = 25
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

MANAUS_TZ = pytz.timezone('America/Manaus')

LEAD_STATUS = {
    'pending': 'Pendente', 'in_use': 'Em Uso', 'completed': 'Concluido',
    'no_answer': 'Nao Atendeu', 'scheduled': 'Agendado', 'busy': 'Ocupado',
    'not_interested': 'Nao Interessado', 'other': 'Outro'
}

# --- FUNCOES DE BANCO DE DADOS E UTILITARIOS ---
def get_db_connection():
    # --- CONEXAO ROBUSTA (CAMADA 2) ---
    try:
        conn = psycopg2.connect(
            dbname="telemarketing_db",
            user="postgres",
            host="127.0.0.1",        # Forca conexao TCP/IP no Windows
            port="5000",
            password="13241218Gui@",
            client_encoding='utf8'   # Parametro critico para o driver
        )
        return conn
    except psycopg2.OperationalError as e:
        print("!!! ERRO DE CONEXAO AO BANCO DE DADOS !!!")
        print(f"!!! Detalhes: {e}")
        print("!!! Por favor, verifique se o PostgreSQL esta rodando e se os dados de conexao estao corretos.")
        raise

def get_current_time():
    return datetime.now(MANAUS_TZ)

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('''CREATE TABLE IF NOT EXISTS users (id SERIAL PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, role TEXT NOT NULL, created_at TIMESTAMP WITH TIME ZONE, session_token TEXT)''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS projects (id SERIAL PRIMARY KEY, name TEXT NOT NULL UNIQUE, created_at TIMESTAMP WITH TIME ZONE, start_date TIMESTAMP WITH TIME ZONE, end_date TIMESTAMP WITH TIME ZONE)''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS leads (id SERIAL PRIMARY KEY, name TEXT NOT NULL, phone TEXT NOT NULL, city TEXT, subject TEXT, custom_fields TEXT, status TEXT DEFAULT 'pending', assigned_to INTEGER, notes TEXT, created_at TIMESTAMP WITH TIME ZONE, updated_at TIMESTAMP WITH TIME ZONE, project_id INTEGER, duration_seconds INTEGER, start_time TIMESTAMP WITH TIME ZONE, scheduled_at TIMESTAMP WITH TIME ZONE, FOREIGN KEY(assigned_to) REFERENCES users(id) ON DELETE SET NULL, FOREIGN KEY(project_id) REFERENCES projects(id) ON DELETE CASCADE)''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS audit_log (id SERIAL PRIMARY KEY, user_id INTEGER, action TEXT NOT NULL, target_type TEXT NOT NULL, target_id INTEGER, details TEXT, timestamp TIMESTAMP WITH TIME ZONE, FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL)''')

    cursor.execute('SELECT COUNT(*) FROM users WHERE role = %s', ('admin',))
    if cursor.fetchone()[0] == 0:
        cursor.execute('INSERT INTO users (username, password_hash, role, created_at) VALUES (%s, %s, %s, %s)', ('admin', generate_password_hash('admin123'), 'admin', get_current_time()))
    conn.commit()
    cursor.close()
    conn.close()

# --- DECORADORES ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or 'token' not in session: return redirect(url_for('login'))
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        cursor.execute('SELECT session_token FROM users WHERE id = %s', (session['user_id'],))
        user = cursor.fetchone()
        cursor.close()
        conn.close()
        if not user or user['session_token'] != session.get('token'):
            session.clear()
            flash('Sua sessao foi encerrada por um novo login em outro local.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if session.get('role') != 'admin':
            flash('Acesso negado. Apenas administradores.', 'error')
            return redirect(url_for('home'))
        return f(*args, **kwargs)
    return decorated_function

def gestor_or_admin_required(f):
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if session.get('role') not in ['admin', 'gestor']:
            flash('Acesso negado. Voce nao tem permissao.', 'error')
            return redirect(url_for('home'))
        return f(*args, **kwargs)
    return decorated_function

def log_audit(user_id, action, target_type, target_id=None, details=None):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute('INSERT INTO audit_log (user_id, action, target_type, target_id, details, timestamp) VALUES (%s, %s, %s, %s, %s, %s)', (user_id, action, target_type, target_id, details, get_current_time()))
        conn.commit()
    finally:
        cursor.close()
        conn.close()

# --- CHAMADA DE INICIALIZACAO DO BANCO DE DADOS ---
init_db()

@app.context_processor
def inject_globals():
    return {'get_current_time': get_current_time, 'LEAD_STATUS': LEAD_STATUS}

# --- ROTAS ---
@app.route('/')
def index():
    return redirect(url_for('login')) if 'user_id' not in session else redirect(url_for('home'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username, password = request.form['username'], request.form['password']
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
        user = cursor.fetchone()
        if user and check_password_hash(user['password_hash'], password):
            new_token = secrets.token_hex(16)
            cursor.execute('UPDATE users SET session_token = %s WHERE id = %s', (new_token, user['id']))
            conn.commit()
            session.clear()
            session['user_id'], session['username'], session['role'], session['token'] = user['id'], user['username'], user['role'], new_token
            log_audit(user['id'], 'login', 'user', user['id'])
            flash('Login realizado com sucesso!', 'success')
            cursor.close()
            conn.close()
            return redirect(url_for('home'))
        else:
            flash('Usuario ou senha invalidos.', 'error')
            cursor.close()
            conn.close()
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('UPDATE users SET session_token = NULL WHERE id = %s', (session['user_id'],))
    conn.commit()
    cursor.close()
    conn.close()
    log_audit(session['user_id'], 'logout', 'user', session['user_id'])
    session.clear()
    flash('Logout realizado com sucesso!', 'success')
    return redirect(url_for('login'))

@app.route('/home')
@login_required
def home():
    if session.get('role') == 'operator': # CORRECAO DO SYNTAX ERROR AQUI
        return redirect(url_for('operator_dashboard'))
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

    cursor.execute("SELECT COUNT(*) FROM leads WHERE status = 'pending'")
    pending_leads = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM leads WHERE status = 'in_use'")
    in_work_leads = cursor.fetchone()[0]

    cursor.execute("SELECT status, COUNT(*) as count FROM leads WHERE status NOT IN ('pending', 'in_use') GROUP BY status")
    finalized_by_status = {LEAD_STATUS.get(row['status'], row['status']): row['count'] for row in cursor.fetchall()}
    cursor.execute("SELECT u.username, COUNT(l.id) as count FROM leads l JOIN users u ON l.assigned_to = u.id WHERE l.status NOT IN ('pending', 'in_use') AND DATE(l.updated_at) = DATE(%s) GROUP BY u.username ORDER BY count DESC", (get_current_time().date(),))
    daily_productivity = cursor.fetchall()
    cursor.execute('SELECT p.name, COUNT(l.id) as count FROM projects p LEFT JOIN leads l ON p.id = l.project_id GROUP BY p.name ORDER BY p.name')
    leads_per_project = cursor.fetchall()

    stats = {
        'pending_leads': pending_leads,
        'in_work_leads': in_work_leads,
        'finalized_by_status': finalized_by_status,
        'daily_productivity': daily_productivity,
        'leads_per_project': leads_per_project
    }

    cursor.close()
    conn.close()
    return render_template('home.html', stats=stats)

@app.route('/operator')
@login_required
def operator_dashboard():
    if session.get('role') != 'operator':
        return redirect(url_for('home'))
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    user_id = session['user_id']
    cursor.execute('SELECT * FROM leads WHERE assigned_to = %s AND status = %s ORDER BY created_at ASC LIMIT 1', (user_id, 'in_use'))
    lead = cursor.fetchone()
    if lead and not lead['start_time']:
        cursor.execute('UPDATE leads SET start_time = %s WHERE id = %s', (get_current_time(), lead['id']))
        conn.commit()
    cursor.execute('SELECT COUNT(*) FROM leads WHERE assigned_to = %s AND status = %s', (user_id, 'in_use'))
    pending_count = cursor.fetchone()[0]
    cursor.execute("SELECT status, COUNT(*) as count FROM leads WHERE assigned_to = %s AND status NOT IN ('pending', 'in_use') AND DATE(updated_at) = DATE(%s) GROUP BY status", (user_id, get_current_time().date()))
    completed_today_stats = {LEAD_STATUS.get(row['status'], row['status']): row['count'] for row in cursor.fetchall()}
    conn.close()
    custom_fields = json.loads(lead['custom_fields']) if lead and lead.get('custom_fields') else {}
    return render_template('operator_dashboard.html', lead=lead, custom_fields=custom_fields, pending_count=pending_count, completed_today_stats=completed_today_stats)

@app.route('/leads/<int:lead_id>/complete', methods=['POST'])
@login_required
def complete_lead(lead_id):
    if session.get('role') != 'operator': return jsonify({'error': 'Acesso negado.'}), 403

    status, notes, scheduled_date = request.form.get('status'), request.form.get('notes', '').strip(), request.form.get('scheduled_date')

    if not status or status not in LEAD_STATUS: return jsonify({'error': 'Status invalido.'}), 400
    if status == 'other' and not notes: return jsonify({'error': 'Para "Outro", a observacao e obrigatoria.'}), 400
    if status == 'scheduled' and not scheduled_date: return jsonify({'error': 'Para "Agendado", a data e obrigatoria.'}), 400

    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    cursor.execute('SELECT id, start_time FROM leads WHERE id = %s AND assigned_to = %s', (lead_id, session['user_id']))
    lead = cursor.fetchone()
    if not lead:
        conn.close()
        return jsonify({'error': 'Dado nao encontrado ou nao atribuido a voce.'}), 404

    duration_seconds = int((get_current_time() - lead['start_time']).total_seconds()) if lead['start_time'] else None

    final_scheduled_at = None
    if status == 'scheduled':
        try:
            naive_dt = datetime.strptime(scheduled_date, '%Y-%m-%dT%H:%M')
            final_scheduled_at = MANAUS_TZ.localize(naive_dt)
        except (ValueError, TypeError):
             conn.close()
             return jsonify({'error': 'Formato de data invalido.'}), 400

    cursor.execute(
        'UPDATE leads SET status = %s, notes = %s, updated_at = %s, duration_seconds = %s, start_time = NULL, scheduled_at = %s WHERE id = %s',
        (status, notes, get_current_time(), duration_seconds, final_scheduled_at, lead_id))
    conn.commit()
    conn.close()

    log_audit(session['user_id'], 'complete', 'lead', lead_id, f'Status: {LEAD_STATUS.get(status, status)}')
    return get_next_lead_for_operator()

@app.route('/operator/next_lead')
@login_required
def get_next_lead_for_operator():
    if session.get('role') != 'operator': return jsonify({'error': 'Acesso negado'}), 403
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    user_id = session['user_id']
    cursor.execute('SELECT * FROM leads WHERE assigned_to = %s AND status = %s ORDER BY created_at ASC LIMIT 1', (user_id, 'in_use'))
    lead = cursor.fetchone()
    if lead:
        cursor.execute('UPDATE leads SET start_time = %s WHERE id = %s', (get_current_time(), lead['id']))
        conn.commit()

    cursor.execute('SELECT COUNT(*) FROM leads WHERE assigned_to = %s AND status = %s', (user_id, 'in_use'))
    pending_count = cursor.fetchone()[0]
    cursor.execute("SELECT status, COUNT(*) as count FROM leads WHERE assigned_to = %s AND status NOT IN ('pending', 'in_use') AND DATE(updated_at) = DATE(%s) GROUP BY status", (user_id, get_current_time().date()))
    completed_today_stats = {LEAD_STATUS.get(row['status'], row['status']): row['count'] for row in cursor.fetchall()}
    conn.close()

    if lead:
        lead_data = dict(lead)
        for k, v in lead_data.items():
            if isinstance(v, datetime):
                lead_data[k] = v.isoformat()
        lead_data['custom_fields'] = json.loads(lead['custom_fields']) if lead.get('custom_fields') else {}
        return jsonify({'lead': lead_data, 'pending_count': pending_count, 'completed_today_stats': completed_today_stats, 'status': 'ok'})
    else:
        return jsonify({'status': 'finished', 'pending_count': pending_count, 'completed_today_stats': completed_today_stats})

@app.route('/leads')
@gestor_or_admin_required
def leads():
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    page = request.args.get('page', 1, type=int)
    per_page = app.config['LEADS_PER_PAGE']
    offset = (page - 1) * per_page
    filters = {k: request.args.get(k, '') for k in ['status', 'operator', 'search', 'project_id']}

    base_query = 'FROM leads l LEFT JOIN users u ON l.assigned_to = u.id LEFT JOIN projects p ON l.project_id = p.id WHERE 1=1'
    params = []
    if filters['project_id']: base_query += ' AND l.project_id = %s'; params.append(int(filters['project_id']))
    if filters['status']: base_query += ' AND l.status = %s'; params.append(filters['status'])
    if filters['operator']: base_query += ' AND u.id = %s'; params.append(int(filters['operator']))
    if filters['search']: base_query += ' AND (l.name LIKE %s OR l.phone LIKE %s)'; params.extend([f"%{filters['search']}%", f"%{filters['search']}%"])

    cursor.execute('SELECT COUNT(l.id) ' + base_query, tuple(params))
    total_leads = cursor.fetchone()[0]
    total_pages = math.ceil(total_leads / per_page) if per_page > 0 else 0

    cursor.execute('SELECT l.*, u.username as operator, p.name as project_name ' + base_query + ' ORDER BY l.id DESC LIMIT %s OFFSET %s', tuple(params) + (per_page, offset))
    leads_data = cursor.fetchall()

    cursor.execute('SELECT id, username FROM users WHERE role = %s ORDER BY username', ('operator',))
    operators = cursor.fetchall()

    cursor.execute('SELECT id, name FROM projects ORDER BY name')
    all_projects = cursor.fetchall()
    conn.close()

    pagination = {'page': page, 'total_pages': total_pages, 'has_prev': page > 1, 'has_next': page < total_pages}

    return render_template('leads.html', leads=leads_data, operators=operators, all_projects=all_projects, LEAD_STATUS=LEAD_STATUS, filters=filters, pagination=pagination)

@app.route('/agendamentos')
@login_required
def agendamentos():
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    query = 'SELECT l.id, l.name, l.phone, l.scheduled_at, u.username as operator, p.name as project_name FROM leads l LEFT JOIN users u ON l.assigned_to = u.id LEFT JOIN projects p ON l.project_id = p.id WHERE l.status = %s'
    params = ['scheduled']
    if session.get('role') == 'operator': # CORRECAO DO SYNTAX ERROR AQUI
        query += ' AND l.assigned_to = %s'
        params.append(session['user_id'])
    query += ' ORDER BY l.scheduled_at ASC'
    cursor.execute(query, tuple(params))
    leads = cursor.fetchall()
    conn.close()
    return render_template('agendamentos.html', leads=leads)

@app.route('/leads/import', methods=['GET', 'POST'])
@gestor_or_admin_required
def import_leads():
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    cursor.execute('SELECT id, name FROM projects ORDER BY name')
    projects = cursor.fetchall()
    conn.close()
    if request.method == 'POST':
        project_id = request.form.get('project_id')
        if not project_id:
            flash('Voce deve selecionar um projeto para importar os dados.', 'error')
            return render_template('import_leads.html', projects=projects)
        if 'file' not in request.files or not request.files['file'].filename:
            flash('Nenhum arquivo selecionado.', 'error')
            return render_template('import_leads.html', projects=projects, selected_project=project_id)
        file = request.files['file']
        if file and file.filename.lower().endswith(('.xlsx', '.xls', '.csv')):
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(file.filename))
            file.save(file_path)
            try:
                df = pd.read_csv(file_path, dtype=str) if file.filename.lower().endswith('.csv') else pd.read_excel(file_path, dtype=str)
                df.fillna('', inplace=True)
                df.columns = [str(col).lower().strip() for col in df.columns]
                name_col = next((c for c in df.columns if c in ['nome', 'entrevistado']), None)
                phone_col = next((c for c in df.columns if c == 'telefone'), None)
                if not name_col or not phone_col:
                    flash('O arquivo deve conter colunas de Nome (ou Entrevistado) e Telefone.', 'error')
                    os.remove(file_path)
                    return render_template('import_leads.html', projects=projects, selected_project=project_id)
                known_cols = {name_col, phone_col, next((c for c in df.columns if c == 'cidade'), None), next((c for c in df.columns if c == 'assunto'), None)}
                custom_cols = [c for c in df.columns if c not in known_cols]
                conn = get_db_connection()
                cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
                imported_count, duplicate_count, error_count = 0, 0, 0
                current_time = get_current_time()
                for _, row in df.iterrows():
                    try:
                        name, phone = str(row.get(name_col, '')).strip(), str(row.get(phone_col, '')).strip()
                        if not name or not phone:
                            error_count += 1
                            continue
                        cursor.execute('SELECT id FROM leads WHERE name = %s AND phone = %s AND project_id = %s', (name, phone, int(project_id)))
                        if cursor.fetchone():
                            duplicate_count += 1
                            continue
                        custom_fields = {col.capitalize(): str(row[col]).strip() for col in custom_cols if str(row[col]).strip()}
                        cursor.execute('INSERT INTO leads (name, phone, custom_fields, created_at, updated_at, project_id) VALUES (%s, %s, %s, %s, %s, %s)',(name, phone, json.dumps(custom_fields) if custom_fields else None,current_time, current_time, int(project_id)))
                        imported_count += 1
                    except Exception as e:
                        print(e)
                        error_count += 1
                conn.commit()
                cursor.execute('SELECT name FROM projects WHERE id = %s', (int(project_id),))
                project_name = cursor.fetchone()['name']
                conn.close()
                log_audit(session['user_id'], 'import', 'leads', int(project_id), f'Para o projeto "{project_name}": {imported_count} importados, {duplicate_count} duplicatas, {error_count} erros')
                flash(f'Importacao concluida! {imported_count} dados importados para o projeto "{project_name}", {duplicate_count} duplicatas ignoradas.', 'success')
                os.remove(file_path)
                return redirect(url_for('leads'))
            except Exception as e:
                flash(f'Erro ao processar o arquivo: {e}', 'error')
                if os.path.exists(file_path): os.remove(file_path)
                return render_template('import_leads.html', projects=projects, selected_project=project_id)
        else:
            flash('Formato de arquivo nao suportado.', 'error')
    return render_template('import_leads.html', projects=projects)

@app.route('/leads/export')
@gestor_or_admin_required
def export_leads():
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    filters = {k: request.args.get(k, '') for k in ['city', 'status', 'operator', 'subject', 'search', 'project_id']}
    query = 'SELECT l.*, u.username as operator, p.name as project_name FROM leads l LEFT JOIN users u ON l.assigned_to = u.id LEFT JOIN projects p ON l.project_id = p.id WHERE 1=1'
    params = []
    if filters['project_id']: query += ' AND l.project_id = %s'; params.append(filters['project_id'])
    if filters['status']: query += ' AND l.status = %s'; params.append(filters['status'])
    if filters['operator']: query += ' AND u.id = %s'; params.append(filters['operator'])
    if filters['search']: query += ' AND (l.name LIKE %s OR l.phone LIKE %s)'; params.extend([f"%{filters['search']}%", f"%{filters['search']}%"])
    query += ' ORDER BY l.created_at DESC'
    cursor.execute(query, tuple(params))
    leads_data = cursor.fetchall()
    conn.close()
    if not leads_data:
        flash('Nenhum dado para exportar com os filtros atuais.', 'warning')
        return redirect(url_for('leads'))

    df = pd.DataFrame([dict(row) for row in leads_data])
    output = io.BytesIO()
    df.to_excel(output, index=False, sheet_name='Dados Exportados')
    output.seek(0)

    timestamp = get_current_time().strftime('%Y%m%d_%H%M%S')
    filename = f'leads_export_{timestamp}.xlsx'

    log_audit(session['user_id'], 'export', 'leads', None, f'Exportados {len(df)} dados com filtros.')
    return send_file(output, download_name=filename, as_attachment=True, mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')

@app.route('/leads/assign_bulk', methods=['POST'])
@gestor_or_admin_required
def assign_bulk_leads():
    data = request.get_json()
    lead_ids, operator_id = data.get('lead_ids'), data.get('operator_id')
    if not lead_ids or not operator_id: return jsonify({'status': 'error', 'message': 'Dados invalidos.'}), 400
    conn = get_db_connection()
    try:
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        cursor.execute('SELECT username FROM users WHERE id = %s', (operator_id,))
        operator = cursor.fetchone()
        if not operator: return jsonify({'status': 'error', 'message': 'Operador nao encontrado.'}), 404

        query = 'UPDATE leads SET assigned_to = %s, status = %s, updated_at = %s WHERE id = ANY(%s)'
        cursor.execute(query, (operator_id, 'in_use', get_current_time(), lead_ids))
        conn.commit()

        if cursor.rowcount > 0:
            log_audit(session['user_id'], 'assign_bulk', 'lead', None, f'{cursor.rowcount} dados para {operator["username"]}')
            flash(f'{cursor.rowcount} dados atribuidos com sucesso!', 'success')
        return jsonify({'status': 'success'})
    finally:
        conn.close()

@app.route('/leads/unassign_bulk', methods=['POST'])
@gestor_or_admin_required
def unassign_bulk_leads():
    data = request.get_json()
    lead_ids = data.get('lead_ids')
    if not lead_ids: return jsonify({'status': 'error', 'message': 'Nenhum ID fornecido.'}), 400
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        query = 'UPDATE leads SET assigned_to = NULL, status = %s, updated_at = %s WHERE id = ANY(%s)'
        cursor.execute(query, ('pending', get_current_time(), lead_ids))
        conn.commit()
        if cursor.rowcount > 0:
            log_audit(session['user_id'], 'unassign_bulk', 'lead', None, f'{cursor.rowcount} dados desatribuidos.')
            flash(f'{cursor.rowcount} dados desatribuidos com sucesso!', 'success')
        return jsonify({'status': 'success'})
    finally:
        conn.close()

@app.route('/leads/assign_by_id_range', methods=['POST'])
@gestor_or_admin_required
def assign_by_id_range():
    data = request.get_json()
    start_id, end_id, operator_id, project_id = data.get('start_id'), data.get('end_id'), data.get('operator_id'), data.get('project_id')
    if not all([start_id, end_id, operator_id, project_id]):
        return jsonify({'status': 'error', 'message': 'Todos os campos sao obrigatorios.'}), 400
    conn = get_db_connection()
    try:
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        cursor.execute('SELECT username FROM users WHERE id = %s AND role = %s', (operator_id, 'operator'))
        operator = cursor.fetchone()
        if not operator:
            return jsonify({'status': 'error', 'message': 'Operador invalido.'}), 404

        query = 'UPDATE leads SET assigned_to = %s, status = %s, updated_at = %s WHERE id >= %s AND id <= %s AND project_id = %s AND status = %s'
        cursor.execute(query, (operator_id, 'in_use', get_current_time(), start_id, end_id, project_id, 'pending'))
        conn.commit()
        count = cursor.rowcount
        log_audit(session['user_id'], 'assign_range', 'lead', None, f'{count} leads (IDs {start_id}-{end_id}) para {operator["username"]}')
        flash(f'{count} leads foram atribuidos com sucesso!', 'success')
        return jsonify({'status': 'success', 'message': f'{count} leads atribuidos.'})
    finally:
        conn.close()

@app.route('/leads/unassign_by_id_range', methods=['POST'])
@gestor_or_admin_required
def unassign_by_id_range():
    data = request.get_json()
    start_id, end_id, project_id = data.get('start_id'), data.get('end_id'), data.get('project_id')
    if not all([start_id, end_id, project_id]):
        return jsonify({'status': 'error', 'message': 'Todos os campos sao obrigatorios.'}), 400
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        query = 'UPDATE leads SET assigned_to = NULL, status = %s, updated_at = %s WHERE id >= %s AND id <= %s AND project_id = %s'
        cursor.execute(query, ('pending', get_current_time(), start_id, end_id, project_id))
        conn.commit()
        count = cursor.rowcount
        log_audit(session['user_id'], 'unassign_range', 'lead', None, f'{count} leads (IDs {start_id}-{end_id}) foram desatribuidos.')
        flash(f'{count} leads foram desatribuidos com sucesso!', 'success')
        return jsonify({'status': 'success', 'message': f'{count} leads desatribuidos.'})
    finally:
        conn.close()

@app.route('/leads/delete_bulk', methods=['POST'])
@admin_required
def delete_bulk_leads():
    data = request.get_json()
    lead_ids = data.get('lead_ids')
    if not lead_ids: return jsonify({'status': 'error', 'message': 'Nenhum ID fornecido.'}), 400
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute('DELETE FROM leads WHERE id = ANY(%s)', (lead_ids,))
        conn.commit()
        if cursor.rowcount > 0:
            log_audit(session['user_id'], 'delete_bulk', 'lead', None, f'{cursor.rowcount} dados excluidos.')
            flash(f'{cursor.rowcount} dados excluidos com sucesso!', 'success')
        return jsonify({'status': 'success'})
    finally:
        conn.close()

@app.route('/leads/<int:lead_id>/unassign', methods=['POST'])
@gestor_or_admin_required
def unassign_lead(lead_id):
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    cursor.execute('SELECT l.name, u.username FROM leads l JOIN users u ON l.assigned_to = u.id WHERE l.id = %s', (lead_id,))
    lead = cursor.fetchone()
    if lead:
        cursor.execute('UPDATE leads SET assigned_to = NULL, status = %s, updated_at = %s WHERE id = %s', ('pending', get_current_time(), lead_id))
        conn.commit()
        log_audit(session['user_id'], 'unassign', 'lead', lead_id, f"Operador '{lead['username']}' desatribuido do dado '{lead['name']}'")
        flash(f"O dado '{lead['name']}' foi desatribuido com sucesso.", 'success')
    else:
        flash('Dado nao encontrado ou ja nao esta atribuido.', 'error')
    conn.close()
    return redirect(url_for('leads'))

@app.route('/leads/<int:lead_id>/edit', methods=['GET', 'POST'])
@admin_required
def edit_lead(lead_id):
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    if request.method == 'POST':
        name, phone, city, subject, notes = request.form['name'], request.form['phone'], request.form.get('city', ''), request.form.get('subject', ''), request.form.get('notes', '')
        custom_fields = {key[7:]: value.strip() for key, value in request.form.items() if key.startswith('custom_') and value.strip()}
        cursor.execute('UPDATE leads SET name = %s, phone = %s, city = %s, subject = %s, notes = %s, custom_fields = %s, updated_at = %s WHERE id = %s',
                       (name, phone, city, subject, notes, json.dumps(custom_fields) if custom_fields else None, get_current_time(), lead_id))
        conn.commit()
        log_audit(session['user_id'], 'update', 'lead', lead_id, f'Dado {name} editado')
        flash('Dado atualizado com sucesso!', 'success')
        conn.close()
        return redirect(url_for('leads'))

    cursor.execute('SELECT * FROM leads WHERE id = %s', (lead_id,))
    lead = cursor.fetchone()
    conn.close()
    if not lead:
        flash('Dado nao encontrado.', 'error')
        return redirect(url_for('leads'))

    custom_fields = json.loads(lead['custom_fields']) if lead and lead['custom_fields'] else {}
    return render_template('edit_lead.html', lead=lead, custom_fields=custom_fields)

@app.route('/leads/<int:lead_id>/delete', methods=['POST'])
@admin_required
def delete_lead(lead_id):
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    cursor.execute('SELECT name FROM leads WHERE id = %s', (lead_id,))
    lead = cursor.fetchone()
    if lead:
        cursor.execute('DELETE FROM leads WHERE id = %s', (lead_id,))
        conn.commit()
        log_audit(session['user_id'], 'delete', 'lead', lead_id, f"Dado '{lead['name']}' excluido")
        flash('Dado excluido com sucesso!', 'success')
    else:
        flash('Dado nao encontrado.', 'error')
    conn.close()
    return redirect(url_for('leads'))

@app.route('/reports')
@gestor_or_admin_required
def reports():
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    cursor.execute('SELECT status, COUNT(*) as count FROM leads GROUP BY status')
    status_distribution_raw = cursor.fetchall()
    status_distribution = { 'labels': [LEAD_STATUS.get(row['status'], row['status']) for row in status_distribution_raw], 'data': [row['count'] for row in status_distribution_raw] }

    cursor.execute('''SELECT u.username, l.status, COUNT(l.id) as count FROM leads l JOIN users u ON l.assigned_to = u.id WHERE l.status NOT IN ('pending', 'in_use') GROUP BY u.username, l.status ORDER BY u.username, l.status''')
    operator_performance_raw = cursor.fetchall()
    operator_performance = {}
    all_status_labels = sorted([v for k, v in LEAD_STATUS.items() if k not in ['pending', 'in_use']])
    operators_with_activity = {row['username'] for row in operator_performance_raw}
    for username in operators_with_activity:
        operator_performance[username] = {status: 0 for status in all_status_labels}
    for row in operator_performance_raw:
        status_label = LEAD_STATUS.get(row['status'], row['status'])
        if row['username'] in operator_performance and status_label in operator_performance[row['username']]:
            operator_performance[row['username']][status_label] = row['count']
    operator_charts_data = {username: {'labels': list(status_counts.keys()), 'data': list(status_counts.values())} for username, status_counts in operator_performance.items()}
    conn.close()
    return render_template('reports.html', status_distribution=status_distribution, operator_charts_data=operator_charts_data)

@app.route('/reports/project/<int:project_id>')
@gestor_or_admin_required
def project_report(project_id):
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    cursor.execute('SELECT * FROM projects WHERE id = %s', (project_id,))
    project = cursor.fetchone()
    if not project:
        flash('Projeto nao encontrado.', 'error')
        conn.close()
        return redirect(url_for('projects'))

    cursor.execute('SELECT status, COUNT(*) as count FROM leads WHERE project_id = %s GROUP BY status', (project_id,))
    status_distribution_raw = cursor.fetchall()
    status_distribution = {'labels': [LEAD_STATUS.get(row['status'], row['status']) for row in status_distribution_raw], 'data': [row['count'] for row in status_distribution_raw]}

    cursor.execute('''SELECT u.username, l.status, COUNT(l.id) as count FROM leads l JOIN users u ON l.assigned_to = u.id WHERE l.status NOT IN ('pending', 'in_use') AND l.project_id = %s GROUP BY u.username, l.status ORDER BY u.username, l.status''', (project_id,))
    operator_performance_raw = cursor.fetchall()
    operator_performance = {}
    all_status_labels = sorted([v for k, v in LEAD_STATUS.items() if k not in ['pending', 'in_use']])
    operators_with_activity = {row['username'] for row in operator_performance_raw}
    for username in operators_with_activity:
        operator_performance[username] = {status: 0 for status in all_status_labels}
    for row in operator_performance_raw:
        status_label = LEAD_STATUS.get(row['status'], row['status'])
        if row['username'] in operator_performance and status_label in operator_performance[row['username']]:
            operator_performance[row['username']][status_label] = row['count']
    operator_charts_data = {username: {'labels': list(status_counts.keys()), 'data': list(status_counts.values())} for username, status_counts in operator_performance.items()}
    conn.close()
    return render_template('project_report.html', project=project, status_distribution=status_distribution, operator_charts_data=operator_charts_data)

@app.route('/reports/export_pdf')
@login_required
def export_reports_pdf():
    flash('Funcionalidade de exportacao para PDF em implementacao.', 'info')
    return redirect(request.referrer or url_for('reports'))

@app.route('/projects')
@gestor_or_admin_required
def projects():
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    cursor.execute('''SELECT p.id, p.name, p.created_at, p.start_date, p.end_date, COUNT(l.id) as lead_count FROM projects p LEFT JOIN leads l ON p.id = l.project_id GROUP BY p.id ORDER BY p.created_at DESC''')
    projects_data = cursor.fetchall()
    conn.close()
    return render_template('projects.html', projects=projects_data)

@app.route('/projects/add', methods=['GET', 'POST'])
@admin_required
def add_project():
    if request.method == 'POST':
        name, start_date, end_date = request.form.get('name', '').strip(), request.form.get('start_date'), request.form.get('end_date')
        if not name:
            flash('O nome do projeto e obrigatorio.', 'error')
            return render_template('add_project.html')
        if start_date and end_date and end_date < start_date:
            flash('A data de fim nao pode ser anterior a data de inicio.', 'error')
            return render_template('add_project.html', name=name, start_date=start_date, end_date=end_date)
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        cursor.execute('SELECT id FROM projects WHERE name = %s', (name,))
        if cursor.fetchone():
            flash('Ja existe um projeto com este nome.', 'error')
            conn.close()
            return render_template('add_project.html', name=name, start_date=start_date, end_date=end_date)

        cursor.execute('INSERT INTO projects (name, created_at, start_date, end_date) VALUES (%s, %s, %s, %s) RETURNING id',
                       (name, get_current_time(), start_date, end_date))
        project_id = cursor.fetchone()['id']
        conn.commit()
        conn.close()
        log_audit(session['user_id'], 'create', 'project', project_id, f'Projeto "{name}" criado')
        flash('Projeto criado com sucesso!', 'success')
        return redirect(url_for('projects'))
    return render_template('add_project.html')

@app.route('/projects/<int:project_id>/edit', methods=['GET', 'POST'])
@admin_required
def edit_project(project_id):
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    cursor.execute('SELECT * FROM projects WHERE id = %s', (project_id,))
    project = cursor.fetchone()
    if not project:
        flash('Projeto nao encontrado.', 'error')
        conn.close()
        return redirect(url_for('projects'))
    if request.method == 'POST':
        name, start_date, end_date = request.form.get('name', '').strip(), request.form.get('start_date'), request.form.get('end_date')
        if not name:
            flash('O nome do projeto e obrigatorio.', 'error')
            return render_template('edit_project.html', project=project)
        if start_date and end_date and end_date < start_date:
            flash('A data de fim nao pode ser anterior a data de inicio.', 'error')
            return render_template('edit_project.html', project=project)
        cursor.execute('SELECT id FROM projects WHERE name = %s AND id != %s', (name, project_id))
        if cursor.fetchone():
            flash('Ja existe um outro projeto com este nome.', 'error')
            return render_template('edit_project.html', project=project)
        cursor.execute('UPDATE projects SET name = %s, start_date = %s, end_date = %s WHERE id = %s', (name, start_date, end_date, project_id))
        conn.commit()
        conn.close()
        log_audit(session['user_id'], 'update', 'project', project_id, f'Projeto "{name}" atualizado')
        flash('Projeto atualizado com sucesso!', 'success')
        return redirect(url_for('projects'))
    conn.close()
    return render_template('edit_project.html', project=project)

@app.route('/projects/<int:project_id>/delete', methods=['POST'])
@admin_required
def delete_project(project_id):
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    cursor.execute('SELECT name FROM projects WHERE id = %s', (project_id,))
    project = cursor.fetchone()
    if project:
        cursor.execute('DELETE FROM projects WHERE id = %s', (project_id,))
        conn.commit()
        log_audit(session['user_id'], 'delete', 'project', project_id, f"Projeto '{project['name']}' e seus dados foram excluidos")
        flash('Projeto e todos os dados associados foram excluidos com sucesso!', 'success')
    else:
        flash('Projeto nao encontrado.', 'error')
    conn.close()
    return redirect(url_for('projects'))

@app.route('/users')
@gestor_or_admin_required
def users():
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    cursor.execute('SELECT id, username, role, created_at FROM users ORDER BY created_at DESC')
    users_data = cursor.fetchall()
    conn.close()
    return render_template('users.html', users=users_data)

@app.route('/users/add', methods=['GET', 'POST'])
@gestor_or_admin_required
def add_user():
    if request.method == 'POST':
        username, password, role = request.form['username'], request.form['password'], request.form['role']
        if session.get('role') == 'gestor' and role == 'admin':
            flash('Voce nao tem permissao para criar usuarios administradores.', 'error')
            return redirect(url_for('users'))
        if not all([username, password, role]) or role not in ['admin', 'gestor', 'operator']:
            flash('Todos os campos sao obrigatorios e o papel deve ser valido.', 'error')
            return render_template('add_user.html')
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        cursor.execute('SELECT id FROM users WHERE username = %s', (username,))
        if cursor.fetchone():
            flash('Nome de usuario ja existe.', 'error')
            conn.close()
            return render_template('add_user.html')

        cursor.execute('INSERT INTO users (username, password_hash, role, created_at) VALUES (%s, %s, %s, %s) RETURNING id',
                       (username, generate_password_hash(password), role, get_current_time()))
        user_id = cursor.fetchone()['id']
        conn.commit()
        conn.close()
        log_audit(session['user_id'], 'create', 'user', user_id, f'Usuario {username} criado')
        flash('Usuario criado com sucesso!', 'success')
        return redirect(url_for('users'))
    return render_template('add_user.html')

@app.route('/users/<int:user_id>/edit', methods=['GET', 'POST'])
@gestor_or_admin_required
def edit_user(user_id):
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))
    user_to_edit = cursor.fetchone()
    if not user_to_edit or (session.get('role') == 'gestor' and user_to_edit['role'] == 'admin'):
        flash('Usuario nao encontrado ou permissao negada.', 'error')
        conn.close()
        return redirect(url_for('users'))
    if request.method == 'POST':
        username, role, new_password = request.form['username'], request.form['role'], request.form.get('password')
        if session.get('role') == 'gestor' and role == 'admin':
            flash('Voce nao pode promover usuarios a administradores.', 'error')
            conn.close()
            return redirect(url_for('edit_user', user_id=user_id))
        cursor.execute('SELECT id FROM users WHERE username = %s AND id != %s', (username, user_id))
        if cursor.fetchone():
            flash('Nome de usuario ja em uso.', 'error')
            conn.close()
            return redirect(url_for('edit_user', user_id=user_id))
        if new_password:
            cursor.execute('UPDATE users SET username = %s, role = %s, password_hash = %s WHERE id = %s',
                           (username, role, generate_password_hash(new_password), user_id))
        else:
            cursor.execute('UPDATE users SET username = %s, role = %s WHERE id = %s', (username, role, user_id))
        conn.commit()
        conn.close()
        log_audit(session['user_id'], 'update', 'user', user_id, f'Usuario {username} atualizado')
        flash('Usuario atualizado com sucesso!', 'success')
        return redirect(url_for('users'))
    conn.close()
    return render_template('edit_user.html', user=user_to_edit)

@app.route('/users/<int:user_id>/delete', methods=['POST'])
@gestor_or_admin_required
def delete_user(user_id):
    if user_id == session['user_id']:
        flash('Voce nao pode excluir a sua propria conta.', 'error')
        return redirect(url_for('users'))
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))
    user_to_delete = cursor.fetchone()
    if not user_to_delete or (session.get('role') == 'gestor' and user_to_delete['role'] == 'admin'):
        flash('Usuario nao encontrado ou permissao negada.', 'error')
        conn.close()
        return redirect(url_for('users'))
    cursor.execute('UPDATE leads SET assigned_to = NULL, status = "pending" WHERE assigned_to = %s', (user_id,))
    cursor.execute('DELETE FROM users WHERE id = %s', (user_id,))
    conn.commit()
    log_audit(session['user_id'], 'delete', 'user', user_id, f"Usuario '{user_to_delete['username']}' excluido")
    flash('Usuario excluido com sucesso!', 'success')
    conn.close()
    return redirect(url_for('users'))

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if session.get('role') == 'operator':
        flash('Acesso negado.', 'error')
        return redirect(url_for('home'))
    if request.method == 'POST':
        current_password, new_password, confirm_password = request.form['current_password'], request.form['new_password'], request.form['confirm_password']
        if new_password != confirm_password:
            flash('Nova senha e confirmacao nao coincidem.', 'error')
            return render_template('change_password.html')
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        cursor.execute('SELECT password_hash FROM users WHERE id = %s', (session['user_id'],))
        user = cursor.fetchone()
        if not user or not check_password_hash(user['password_hash'], current_password):
            flash('Senha atual incorreta.', 'error')
            conn.close()
            return render_template('change_password.html')
        cursor.execute('UPDATE users SET password_hash = %s WHERE id = %s', (generate_password_hash(new_password), session['user_id']))
        conn.commit()
        conn.close()
        log_audit(session['user_id'], 'change_password', 'user', session['user_id'])
        flash('Senha alterada com sucesso!', 'success')
        return redirect(url_for('home'))
    return render_template('change_password.html')

@app.route('/logs')
@admin_required
def logs():
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    filters = {k: request.args.get(k, '') for k in ['user', 'action', 'start_date', 'end_date']}
    query = 'SELECT a.*, u.username, u.role FROM audit_log a LEFT JOIN users u ON a.user_id = u.id WHERE 1=1'
    params = []
    if filters['user']: query += ' AND u.id = %s'; params.append(filters['user'])
    if filters['action']: query += ' AND a.action = %s'; params.append(filters['action'])
    if filters['start_date']: query += ' AND DATE(a.timestamp) >= %s'; params.append(filters['start_date'])
    if filters['end_date']: query += ' AND DATE(a.timestamp) <= %s'; params.append(filters['end_date'])
    query += ' ORDER BY a.timestamp DESC'
    cursor.execute(query, tuple(params))
    logs_data = cursor.fetchall()

    cursor.execute("SELECT id, username FROM users ORDER BY username")
    users = cursor.fetchall()

    cursor.execute('SELECT DISTINCT action FROM audit_log ORDER BY action')
    actions = [row['action'] for row in cursor.fetchall()]

    conn.close()
    return render_template('logs.html', logs=logs_data, users=users, actions=actions, filters=filters)

@app.route('/logs/export')
@admin_required
def export_logs():
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    filters = {k: request.args.get(k, '') for k in ['user', 'action', 'start_date', 'end_date']}
    query = 'SELECT a.timestamp, u.username, u.role, a.action, a.target_type, a.target_id, a.details FROM audit_log a LEFT JOIN users u ON a.user_id = u.id WHERE 1=1'
    params = []
    if filters['user']: query += ' AND u.id = %s'; params.append(filters['user'])
    if filters['action']: query += ' AND a.action = %s'; params.append(filters['action'])
    if filters['start_date']: query += ' AND DATE(a.timestamp) >= %s'; params.append(filters['start_date'])
    if filters['end_date']: query += ' AND DATE(a.timestamp) <= %s'; params.append(filters['end_date'])
    query += ' ORDER BY a.timestamp DESC'
    cursor.execute(query, tuple(params))
    logs_data = cursor.fetchall()
    conn.close()
    if not logs_data:
        flash('Nenhum log para exportar com os filtros atuais.', 'warning')
        return redirect(url_for('logs'))
    df = pd.DataFrame([dict(row) for row in logs_data])
    column_mapping = {
        'timestamp': 'Data/Hora', 'username': 'Usuario', 'role': 'Papel',
        'action': 'Acao', 'target_type': 'Alvo', 'target_id': 'ID do Alvo', 'details': 'Detalhes'
    }
    df = df.rename(columns=column_mapping)
    df['Data/Hora'] = pd.to_datetime(df['Data/Hora']).dt.strftime('%d/%m/%Y %H:%M:%S')
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        df.to_excel(writer, index=False, sheet_name='Logs_Auditoria')
    output.seek(0)
    timestamp = get_current_time().strftime('%Y%m%d_%H%M%S')
    filename = f'Relatorio_Logs_{timestamp}.xlsx'
    log_audit(session['user_id'], 'export', 'logs', None, f'Exportados {len(df)} registros de log.')
    return send_file(output, download_name=filename, as_attachment=True, mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')

if __name__ == '__main__':
    # Roda a aplicacao na porta 5001 para nao conflitar com o PostgreSQL
    app.run(debug=True, host='0.0.0.0', port=5001)
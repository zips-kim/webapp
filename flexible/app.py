import os
import io
import json
import math
import sqlite3
import time
import pandas as pd
from flask import Flask, render_template, request, redirect, url_for, flash, send_file, g, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user

# ==========================================
# 1. 설정 및 초기화 (Configuration)
# ==========================================
app = Flask(__name__)
app.secret_key = 'super_secret_key' # 실서비스 시 변경 권장
DB_NAME = "flex_system_v2.db"

# [안정화] 절대 경로 사용으로 경로 에러 방지
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'static', 'uploads')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'xlsx', 'docx', 'xls'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# [안정화] 템플릿 기능 확장 (do, loop 등 지원)
app.jinja_env.add_extension('jinja2.ext.do')
app.jinja_env.add_extension('jinja2.ext.loopcontrols')

# Flask-Login 설정
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# [안정화] JSON 파싱 에러 방지 헬퍼
def safe_json_loads(json_str):
    try:
        if not json_str: return {}
        return json.loads(json_str)
    except:
        return {}

# ==========================================
# 2. 데이터베이스 (Database Helper)
# ==========================================
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DB_NAME)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    """DB 테이블 및 기본 데이터 초기화"""
    with app.app_context():
        db = get_db()
        # 테이블 생성 쿼리 모음
        queries = [
            'CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, password TEXT, name TEXT, is_admin INTEGER DEFAULT 0)',
            'CREATE TABLE IF NOT EXISTS forms (id INTEGER PRIMARY KEY, title TEXT, schema_json TEXT, view_type TEXT DEFAULT "list", page_limit INTEGER DEFAULT 10, sort_order INTEGER DEFAULT 999, access_create TEXT DEFAULT "", access_update TEXT DEFAULT "", access_delete TEXT DEFAULT "", category TEXT DEFAULT "general")',
            'CREATE TABLE IF NOT EXISTS entries (id INTEGER PRIMARY KEY, form_id INTEGER, data_json TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)',
            'CREATE TABLE IF NOT EXISTS menus (id INTEGER PRIMARY KEY, title TEXT, url TEXT, icon TEXT, type TEXT, parent_id INTEGER, sort_order INTEGER DEFAULT 0, allowed_users TEXT DEFAULT "")',
            'CREATE TABLE IF NOT EXISTS history (id INTEGER PRIMARY KEY, entry_id INTEGER, user_name TEXT, action TEXT, details TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)'
        ]
        
        for q in queries:
            db.execute(q)
        
        # 컬럼 추가 (마이그레이션) - 에러 무시 (이미 존재할 경우)
        alter_queries = [
            'ALTER TABLE users ADD COLUMN is_admin INTEGER DEFAULT 0',
            'ALTER TABLE forms ADD COLUMN page_limit INTEGER DEFAULT 10',
            'ALTER TABLE forms ADD COLUMN view_type TEXT DEFAULT "list"',
            'ALTER TABLE menus ADD COLUMN allowed_users TEXT DEFAULT ""',
            'ALTER TABLE forms ADD COLUMN access_create TEXT DEFAULT ""',
            'ALTER TABLE forms ADD COLUMN access_update TEXT DEFAULT ""',
            'ALTER TABLE forms ADD COLUMN access_delete TEXT DEFAULT ""',
            'ALTER TABLE forms ADD COLUMN category TEXT DEFAULT "general"'
        ]
        for q in alter_queries:
            try: db.execute(q)
            except: pass
        
        # 관리자 계정 생성 (없으면 생성)
        if not db.execute('SELECT 1 FROM users WHERE id = "admin"').fetchone():
            hashed_pw = generate_password_hash("1234")
            db.execute('INSERT INTO users (id, name, password, is_admin) VALUES (?, ?, ?, ?)', ("admin", "슈퍼관리자", hashed_pw, 1))
        
        db.commit()

# ==========================================
# 3. 사용자 인증 (Authentication)
# ==========================================
class User(UserMixin):
    def __init__(self, id, name, password, is_admin=0):
        self.id = id
        self.name = name
        self.password = password
        self.is_admin = is_admin

# [NEW] 권한 체크 헬퍼 함수 (전역 사용)
def has_permission(form_def, action):
    """
    action: 'create', 'update', 'delete'
    return: True/False
    """
    if not current_user.is_authenticated: return False
    if current_user.is_admin: return True # 슈퍼관리자는 무조건 통과

    # 컬럼명 매핑
    col_map = {
        'create': 'access_create',
        'update': 'access_update',
        'delete': 'access_delete'
    }
    
    allowed_str = form_def[col_map[action]]
    
    # 설정된 값이 없으면(빈 문자열) => '전체 허용'으로 간주 (기본값)
    if not allowed_str or allowed_str.strip() == "":
        return True
        
    allowed_list = allowed_str.split(',')
    return current_user.id in allowed_list

# Context Processor에 등록하여 템플릿에서 함수처럼 사용 가능하게 함
@app.context_processor
def utility_processor():
    return dict(has_permission=has_permission)
    
@login_manager.user_loader
def load_user(user_id):
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    if not user: return None
    is_admin = user['is_admin'] if 'is_admin' in user.keys() else 0
    return User(id=user['id'], name=user['name'], password=user['password'], is_admin=is_admin)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user_id = request.form['user_id']
        password = request.form['password']
        db = get_db()
        user_data = db.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
        
        if user_data and check_password_hash(user_data['password'], password):
            is_admin = user_data['is_admin'] if 'is_admin' in user_data.keys() else 0
            user = User(id=user_data['id'], name=user_data['name'], password=user_data['password'], is_admin=is_admin)
            login_user(user)
            flash(f'환영합니다, {user.name}님!', 'success')
            return redirect(request.args.get('next') or url_for('home'))
        else:
            flash('아이디 또는 비밀번호가 올바르지 않습니다.', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('로그아웃 되었습니다.', 'info')
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        user_id = request.form['user_id']
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        if db.execute('SELECT 1 FROM users WHERE id = ?', (user_id,)).fetchone():
            flash('이미 존재하는 아이디입니다.', 'danger')
            return redirect(url_for('register'))
        hashed_pw = generate_password_hash(password)
        db.execute('INSERT INTO users (id, name, password) VALUES (?, ?, ?)', (user_id, username, hashed_pw))
        db.commit()
        flash('가입 완료! 로그인하세요.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

# ==========================================
# 4. 메뉴 관리 (Menu Management)
# ==========================================
def build_menu_tree(items):
    item_map = {item['id']: dict(item) for item in items}
    for item in item_map.values(): item['children'] = []
    tree = []
    for item in item_map.values():
        parent_id = item['parent_id']
        if parent_id and parent_id in item_map and parent_id != item['id']:
            item_map[parent_id]['children'].append(item)
        else:
            tree.append(item)
    tree.sort(key=lambda x: (x['sort_order'] if x['sort_order'] is not None else 9999, x['id']))
    return tree

# 2. 메뉴 저장 로직 수정 (권한 저장)
@app.route('/menus/save', methods=['POST'])
@login_required
def save_menu():
    db = get_db()
    try:
        menu_id = request.form.get('menu_id')
        title = request.form.get('title')
        menu_type = request.form.get('type')
        icon = request.form.get('icon')
        
        # [NEW] 권한 데이터 수집
        allowed_list = request.form.getlist('allowed_users')
        allowed_str = ",".join(allowed_list)

        url = ""
        if menu_type == 'form':
            url = f"/list/{request.form.get('target_form_id')}"
        elif menu_type == 'system':
            url = request.form.get('url_manual')
        else:
            url = "#"
        
        if menu_id:
            # [수정] UPDATE 문에 allowed_users 추가
            db.execute('UPDATE menus SET title=?, type=?, url=?, icon=?, allowed_users=? WHERE id=?', 
                       (title, menu_type, url, icon, allowed_str, menu_id))
        else:
            # [수정] INSERT 문에 allowed_users 추가
            db.execute('INSERT INTO menus (title, type, url, icon, allowed_users, sort_order) VALUES (?, ?, ?, ?, ?, 999)', 
                       (title, menu_type, url, icon, allowed_str))
        db.commit()
        return redirect(url_for('manage_menus'))
    except Exception as e:
        return f"저장 오류: {e}"


# 3. 메뉴 관리 페이지 수정 (사용자 목록 전달)
@app.route('/menus', methods=['GET', 'POST'])
@login_required
def manage_menus():
    # 1. 관리자 권한 체크
    if not current_user.is_admin:
        flash("관리자 권한이 필요합니다.", "danger")
        return redirect(url_for('home'))
        
    db = get_db()
    if request.method == 'POST':
        # ... (순서 저장 로직 기존 동일) ...
        try:
            for item in request.json.get('tree', []):
                pid = item.get('parent_id')
                if pid == 'null' or pid == '': pid = None
                db.execute('UPDATE menus SET parent_id = ?, sort_order = ? WHERE id = ?', (pid, item['order'], item['id']))
            db.commit()
            return jsonify({'status': 'success'})
        except Exception as e:
            db.rollback()
            return jsonify({'status': 'error', 'message': str(e)}), 500

    # [NEW] 사용자 목록도 함께 조회 (admin 제외하거나 포함하거나 정책에 따라)
    all_users = db.execute('SELECT id, name FROM users').fetchall()
    
    menus = db.execute('SELECT * FROM menus ORDER BY sort_order ASC').fetchall()
    forms = db.execute('SELECT id, title FROM forms ORDER BY id DESC').fetchall()
    
    # [NEW] render_template에 all_users 전달
    return render_template('menus.html', menu_tree=build_menu_tree(menus), forms=forms, all_users=all_users)


# 4. 사이드바 메뉴 주입 로직 수정 (권한 필터링)
@app.context_processor
def inject_menu_list():
    db = get_db()
    try:
        # [수정] allowed_users 컬럼을 가져와야 수정 시 체크박스가 채워집니다.
        menus = db.execute('SELECT id, title, type, url, icon, parent_id, sort_order, allowed_users FROM menus ORDER BY sort_order ASC').fetchall()
        
        # 로그인 상태 체크 및 권한 필터링
        current_user_id = current_user.id if current_user.is_authenticated else None
        is_admin = current_user.is_admin if current_user.is_authenticated else False

        filtered_menus = []
        for m in menus:
            allowed = m['allowed_users']
            
            # 1. 관리자는 무조건 통과
            if is_admin:
                filtered_menus.append(m)
                continue
            
            # 2. 빈 값은 전체 공개
            if not allowed or allowed.strip() == "":
                filtered_menus.append(m)
                continue
            
            # 3. 특정 사용자 지정된 경우
            if current_user_id and current_user_id in allowed.split(','):
                filtered_menus.append(m)
        
        return dict(menu_tree=build_menu_tree(filtered_menus))
    except: return dict(menu_tree=[])
    
    
@app.route('/menus/delete', methods=['POST'])
@login_required
def delete_menu():
    db = get_db()
    menu_id = request.form.get('menu_id')
    db.execute('DELETE FROM menus WHERE id = ?', (menu_id,))
    db.execute('UPDATE menus SET parent_id = NULL WHERE parent_id = ?', (menu_id,))
    db.commit()
    return redirect(url_for('manage_menus'))

# ==========================================
# 5. 폼 정의 관리 (Form Management)
# ==========================================
@app.route('/create', methods=['GET', 'POST'])
@login_required
def create_form():
    if request.method == 'POST':
        save_form_definition()
        flash("새 시스템이 생성되었습니다.", "success")
        return redirect(url_for('home'))
    db = get_db()
    all_forms = db.execute('SELECT id, title FROM forms').fetchall()
    all_users = db.execute('SELECT id, name FROM users').fetchall()
    return render_template('create.html', mode='create', all_forms=all_forms, all_users=all_users)

@app.route('/edit/<int:form_id>', methods=['GET', 'POST'])
@login_required
def edit_form(form_id):
    db = get_db()
    if request.method == 'POST':
        save_form_definition(form_id=form_id, is_new=False)
        flash("설정이 수정되었습니다.", "success")
        return redirect(url_for('list_entries', form_id=form_id))
    form_def = db.execute('SELECT * FROM forms WHERE id = ?', (form_id,)).fetchone()
    schema = safe_json_loads(form_def['schema_json'])
    all_forms = db.execute('SELECT id, title FROM forms').fetchall()
    all_users = db.execute('SELECT id, name FROM users').fetchall()
    return render_template('create.html', mode='edit', form_def=form_def, schema=schema, all_forms=all_forms, all_users=all_users)

def save_form_definition(form_id=None, is_new=True):
    db = get_db()
    title = request.form['title']
    view_type = request.form.get('view_type', 'list')
    try: page_limit = int(request.form.get('page_limit', 10))
    except: page_limit = 10
    
    acc_create = ",".join(request.form.getlist('access_create'))
    acc_update = ",".join(request.form.getlist('access_update'))
    acc_delete = ",".join(request.form.getlist('access_delete'))
    
    f_names = request.form.getlist('field_name[]')
    f_types = request.form.getlist('field_type[]')
    f_reqs = request.form.getlist('field_required[]')
    f_uniqs = request.form.getlist('field_unique[]')
    f_shows = request.form.getlist('field_show_list[]')
    f_rels = request.form.getlist('field_target[]')
    f_widgets = request.form.getlist('field_widget[]')
    f_options = request.form.getlist('field_options[]')
    category = request.form.get('category', 'general')

    schema = []
    for i in range(len(f_names)):
        if not f_names[i].strip(): continue
        field_def = {
            "key": f_names[i], "label": f_names[i], "type": f_types[i],
            "required": (str(i) in f_reqs), "unique": (str(i) in f_uniqs),
            "show_list": (str(i) in f_shows), "target_id": f_rels[i] if i < len(f_rels) else None,
            "widget": f_widgets[i] if i < len(f_widgets) else 'select',
            "options": f_options[i] if i < len(f_options) else "" 
        }
        schema.append(field_def)
    
    json_str = json.dumps(schema, ensure_ascii=False)
    if is_new:
        db.execute('''INSERT INTO forms (title, schema_json, view_type, page_limit, 
                      access_create, access_update, access_delete, category) 
                      VALUES (?, ?, ?, ?, ?, ?, ?, ?)''', 
                   (title, json_str, view_type, page_limit, acc_create, acc_update, acc_delete, category))
    else:
        db.execute('''UPDATE forms SET title=?, schema_json=?, view_type=?, page_limit=?, 
                      access_create=?, access_update=?, access_delete=?, category=? WHERE id=?''', 
                   (title, json_str, view_type, page_limit, acc_create, acc_update, acc_delete, category, form_id))
    db.commit()

@app.route('/form/delete/<int:form_id>', methods=['POST'])
@login_required
def delete_form(form_id):
    db = get_db()
    try:
        db.execute('DELETE FROM entries WHERE form_id = ?', (form_id,))
        db.execute('DELETE FROM menus WHERE url = ?', (f"/list/{form_id}",))
        db.execute('DELETE FROM forms WHERE id = ?', (form_id,))
        db.commit()
        flash("삭제되었습니다.", "success")
    except Exception as e:
        db.rollback()
        flash(f"삭제 중 오류 발생: {e}", "danger")
    return redirect(url_for('home'))

# ==========================================
# 6. 데이터 관리 (Entry Management)
# ==========================================

# 헬퍼 함수들
def _load_relation_options(db, schema):
    options = {}
    for field in schema:
        if field['type'] == 'relation' and field.get('target_id'):
            rows = db.execute('SELECT id, data_json FROM entries WHERE form_id = ?', (field['target_id'],)).fetchall()
            opt_list = []
            for r in rows:
                d = safe_json_loads(r['data_json'])
                text = list(d.values())[0] if d else f"ID:{r['id']}"
                opt_list.append({"id": str(r['id']), "text": text})
            options[field['key']] = opt_list
    return options

def _handle_file_upload(file):
    if file and file.filename != '' and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        save_name = f"{int(time.time())}_{filename}"
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], save_name))
        return save_name
    return ""

def _check_unique(db, form_id, key, val, exclude_id=None):
    query = f"SELECT 1 FROM entries WHERE form_id = ? AND json_extract(data_json, '$.{key}') = ?"
    params = [form_id, val]
    if exclude_id:
        query += " AND id != ?"
        params.append(exclude_id)
    return db.execute(query, params).fetchone() is not None

# [NEW] 관계형 ID를 실제 텍스트(이름)로 변환하는 함수
def _resolve_relation_labels(db, val):
    if not val: return ""
    # 값이 리스트가 아니면 리스트로 변환 (단일 ID도 리스트로 처리)
    ids = val if isinstance(val, list) else [val]
    labels = []
    
    for entry_id in ids:
        try:
            # ID가 비어있으면 패스
            if not str(entry_id).strip(): continue
            
            # DB에서 해당 ID의 데이터 조회
            row = db.execute('SELECT data_json FROM entries WHERE id = ?', (entry_id,)).fetchone()
            if row:
                d = json.loads(row['data_json'])
                # 첫 번째 값(대표 이름) 가져오기
                first_val = list(d.values())[0] if d else str(entry_id)
                labels.append(str(first_val))
            else:
                labels.append(str(entry_id)) # 데이터가 없으면 그냥 ID 표시
        except:
            labels.append(str(entry_id)) # 에러나면 ID 표시
            
    return ", ".join(labels)
    
def get_diff_text(db, schema, old_data, new_data):
    changes = []
    for field in schema:
        key = field['key']
        label = field['label']
        if field['type'] == 'file': continue

        v_old = old_data.get(key, "")
        v_new = new_data.get(key, "")
        
        # None 값을 빈 문자열로 통일
        if v_old is None: v_old = ""
        if v_new is None: v_new = ""

        # 리스트인 경우 정렬해서 비교 (순서만 바뀐건 변경 아님)
        # (원본 데이터 보호를 위해 복사본 사용 추천하지만, 여기선 단순 비교)
        comp_old = sorted(v_old) if isinstance(v_old, list) else str(v_old)
        comp_new = sorted(v_new) if isinstance(v_new, list) else str(v_new)

        if str(comp_old) != str(comp_new):
            # [핵심] 관계형 필드면 ID -> 이름 변환
            if field['type'] == 'relation':
                old_text = _resolve_relation_labels(db, v_old)
                new_text = _resolve_relation_labels(db, v_new)
            else:
                old_text = str(v_old)
                new_text = str(v_new)
                # 내용이 너무 길면 줄임표 처리
                if len(old_text) > 20: old_text = old_text[:20] + "..."
                if len(new_text) > 20: new_text = new_text[:20] + "..."
            
            changes.append(f"[{label}] {old_text} → {new_text}")
            
    return ", ".join(changes)

def log_history(db, entry_id, action, details=""):
    try:
        user_name = current_user.name if current_user.is_authenticated else "Unknown"
        db.execute('INSERT INTO history (entry_id, user_name, action, details) VALUES (?, ?, ?, ?)',
                   (entry_id, user_name, action, details))
    except: pass # 로그 저장 실패로 본동작이 멈추지 않게

@app.route('/list/<int:form_id>')
@login_required
def list_entries(form_id):
    db = get_db()
    form_def = db.execute('SELECT * FROM forms WHERE id = ?', (form_id,)).fetchone()
    if not form_def: return "존재하지 않는 폼입니다.", 404
    
    schema = safe_json_loads(form_def['schema_json'])
    per_page = form_def['page_limit'] if form_def['page_limit'] else 10
    page = request.args.get('page', 1, type=int)
    search_query = request.args.get('q', '')

    base_query = "FROM entries WHERE form_id = ?"
    params = [form_id]

    if search_query:
        base_query += " AND data_json LIKE ?"
        params.append(f"%{search_query}%")

    current_filters = {}
    for field in schema:
        key = field['key']
        if field['type'] == 'date':
            start_val = request.args.get(f"start_{key}")
            end_val = request.args.get(f"end_{key}")
            if start_val:
                base_query += f" AND json_extract(data_json, '$.{key}') >= ?"
                params.append(start_val)
                current_filters[f"start_{key}"] = start_val
            if end_val:
                base_query += f" AND json_extract(data_json, '$.{key}') <= ?"
                params.append(end_val)
                current_filters[f"end_{key}"] = end_val
        else:
            filter_key = f"filter_{key}"
            val = request.args.get(filter_key)
            if val:
                base_query += f" AND json_extract(data_json, '$.{key}') LIKE ?"
                params.append(f"%{val}%")
                current_filters[filter_key] = val

    total_count = db.execute(f"SELECT COUNT(*) {base_query}", params).fetchone()[0]
    total_pages = math.ceil(total_count / per_page)
    offset = (page - 1) * per_page
    rows = db.execute(f"SELECT * {base_query} ORDER BY id DESC LIMIT ? OFFSET ?", params + [per_page, offset]).fetchall()
    
    data_list = []
    for row in rows:
        data_list.append({
            "id": row['id'], 
            "created_at": row['created_at'], 
            "data": safe_json_loads(row['data_json'])
        })

    filter_options = _load_relation_options(db, schema)
    
    # 룩업 맵 (ID -> 텍스트 변환용)
    lookup_map = {}
    for field in schema:
        if field['type'] == 'relation' and field.get('target_id'):
            opts = filter_options.get(field['key'], [])
            lookup_map[field['key']] = {opt['id']: opt['text'] for opt in opts}

    return render_template('list.html', 
                           form=form_def, schema=schema, data_list=data_list, 
                           lookup_map=lookup_map, page=page, total_pages=total_pages, 
                           total_count=total_count, search_query=search_query, 
                           filter_options=filter_options, current_filters=current_filters,
                           limit=per_page)

@app.route('/entry/create/<int:form_id>', methods=['GET', 'POST'])
@login_required
def create_entry(form_id):
    db = get_db()
    form_def = db.execute('SELECT * FROM forms WHERE id = ?', (form_id,)).fetchone()
    
    # [NEW] 권한 체크
    if not has_permission(form_def, 'create'):
        flash("데이터 등록 권한이 없습니다.", "danger")
        return redirect(url_for('list_entries', form_id=form_id))
        
    schema = safe_json_loads(form_def['schema_json'])
    relation_options = _load_relation_options(db, schema)

    if request.method == 'POST':
        input_data = {}
        error_msg = None
        for field in schema:
            key = field['key']
            if field['type'] == 'file':
                val = _handle_file_upload(request.files.get(key))
            elif field['type'] == 'relation' and field.get('widget') == 'checkbox':
                val = request.form.getlist(key)
            else:
                val = request.form.get(key)
            
            if field.get('unique') and val:
                if _check_unique(db, form_id, key, val):
                    error_msg = f"중복 에러: '{field['label']}' 값은 이미 존재합니다."
                    break
            input_data[key] = val

        if error_msg:
            flash(error_msg, 'danger')
            return render_template('input.html', form=form_def, schema=schema, relation_options=relation_options, saved_input=input_data)
        
        cursor = db.execute('INSERT INTO entries (form_id, data_json) VALUES (?, ?)', (form_id, json.dumps(input_data, ensure_ascii=False)))
        log_history(db, cursor.lastrowid, "생성", "최초 등록")
        db.commit()
        flash("저장되었습니다.", 'success')
        return redirect(url_for('list_entries', form_id=form_id))

    return render_template('input.html', form=form_def, schema=schema, relation_options=relation_options)

@app.route('/entry/edit/<int:entry_id>', methods=['GET', 'POST'])
@login_required
def edit_entry(entry_id):
    db = get_db()
    
    # 1. [순서 중요] entry 데이터를 먼저 가져와야 합니다.
    entry = db.execute('SELECT * FROM entries WHERE id = ?', (entry_id,)).fetchone()
    
    # 2. 데이터 존재 여부 확인
    if not entry:
        flash("존재하지 않는 데이터입니다.", "danger")
        return redirect(url_for('home'))
    
    # 3. 폼 정보 가져오기 (권한 체크 및 화면 구성을 위해)
    form_id = entry['form_id']
    form_def = db.execute('SELECT * FROM forms WHERE id = ?', (form_id,)).fetchone()
    
    # 4. [NEW] 권한 체크 (데이터를 가져온 후에 수행)
    if not has_permission(form_def, 'update'):
        flash("데이터 수정 권한이 없습니다.", "danger")
        return redirect(url_for('list_entries', form_id=form_id))
    
    saved_data = safe_json_loads(entry['data_json'])
    form_id = entry['form_id']
    form_def = db.execute('SELECT * FROM forms WHERE id = ?', (form_id,)).fetchone()
    schema = safe_json_loads(form_def['schema_json'])
    relation_options = _load_relation_options(db, schema)
    
    page = request.args.get('page', 1, type=int)

    if request.method == 'POST':
        input_data = {}
        error_msg = None
        for field in schema:
            key = field['key']
            if field['type'] == 'file':
                file = request.files.get(key)
                if file and file.filename:
                    val = _handle_file_upload(file)
                else:
                    val = saved_data.get(key, "")
            elif field['type'] == 'relation' and field.get('widget') == 'checkbox':
                val = request.form.getlist(key)
            else:
                val = request.form.get(key)
            
            if field.get('unique') and val:
                if _check_unique(db, form_id, key, val, exclude_id=entry_id):
                    error_msg = f"중복 에러: '{field['label']}' 값은 이미 존재합니다."
                    break
            input_data[key] = val

        if error_msg:
            flash(error_msg, 'danger')
            input_data['id'] = entry_id 
            history_list = db.execute('SELECT * FROM history WHERE entry_id=? ORDER BY created_at DESC', (entry_id,)).fetchall()
            return render_template('input.html', form=form_def, schema=schema, relation_options=relation_options, saved_input=input_data, entry_id=entry_id, mode='edit', page=page, history_list=history_list)

        diff = get_diff_text(db, schema, saved_data, input_data)
        
        if diff: 
            log_history(db, entry_id, "수정", diff)

        db.execute('UPDATE entries SET data_json = ? WHERE id = ?', (json.dumps(input_data, ensure_ascii=False), entry_id))
        db.commit()
        
        flash("수정되었습니다.", 'success')
        return redirect(url_for('list_entries', form_id=form_id, page=page))

    # [GET] 화면 렌더링 준비
    
    # [추가] 역방향 참조 데이터 가져오기 (나를 참조하는 데이터들)
    reverse_refs = get_reverse_references(db, form_id, entry_id)

    history_list = db.execute('SELECT * FROM history WHERE entry_id=? ORDER BY created_at DESC', (entry_id,)).fetchall()
    saved_data['id'] = entry['id']
    
    return render_template('input.html', 
                           form=form_def, 
                           schema=schema, 
                           relation_options=relation_options, 
                           saved_input=saved_data, 
                           entry_id=entry_id, 
                           mode='edit', 
                           page=page, 
                           history_list=history_list,
                           reverse_refs=reverse_refs) # [중요] 변수 전달

def get_reverse_references(db, current_form_id, current_entry_id):
    references = []
    # 1. 모든 폼 가져오기
    all_forms = db.execute('SELECT id, title, schema_json FROM forms').fetchall()
    
    for form in all_forms:
        if form['id'] == current_form_id: continue # 자기 자신 제외
        
        # 스키마 파싱 (에러 방지)
        try: schema = json.loads(form['schema_json'])
        except: continue
        
        # 2. 현재 폼(current_form_id)을 참조하는 필드 찾기
        target_fields = [f for f in schema if f['type'] == 'relation' and str(f.get('target_id')) == str(current_form_id)]
        
        for field in target_fields:
            # 3. 데이터 검색 (LIKE로 1차 필터링)
            query = f"SELECT id, data_json FROM entries WHERE form_id = ? AND json_extract(data_json, '$.{field['key']}') LIKE ?"
            rows = db.execute(query, (form['id'], f'%{current_entry_id}%')).fetchall()
            
            connected_list = []
            for r in rows:
                d = json.loads(r['data_json'])
                val = d.get(field['key'])
                
                # 4. 정확한 값 매칭 (ID 확인)
                is_match = False
                if isinstance(val, list): # 체크박스 등 다중 선택
                    if str(current_entry_id) in [str(v) for v in val]: is_match = True
                else: # 단일 선택
                    if str(val) == str(current_entry_id): is_match = True
                
                if is_match:
                    label = list(d.values())[0] if d else f"ID:{r['id']}"
                    connected_list.append({'id': r['id'], 'label': label})
            
            # 5. 결과가 있으면 리스트에 추가
            if connected_list:
                references.append({
                    'form_title': form['title'],
                    'field_label': field['label'],
                    'children': connected_list  # [수정] 'items' -> 'children' (충돌 방지)
                })
                
    return references
    
# [업그레이드] 삭제 시 참조 무결성 체크 (하위 데이터가 있으면 삭제 방지)
@app.route('/entry/delete/<int:entry_id>', methods=['POST'])
@login_required
def delete_entry(entry_id):
    db = get_db()
    entry = db.execute('SELECT * FROM entries WHERE id = ?', (entry_id,)).fetchone()
    if entry:
        form_def = db.execute('SELECT * FROM forms WHERE id = ?', (entry['form_id'],)).fetchone()
        
        # [NEW] 권한 체크
        if not has_permission(form_def, 'delete'):
            flash("데이터 삭제 권한이 없습니다.", "danger")
            return redirect(url_for('list_entries', form_id=form_def['id']))
    
    # 1. 삭제 대상 확인
    target = db.execute('SELECT form_id, data_json FROM entries WHERE id = ?', (entry_id,)).fetchone()
    if not target:
        return "삭제할 데이터를 찾을 수 없습니다.", 404
        
    form_id = target['form_id']
    
    # 2. [중요] 나를 참조하고 있는 데이터가 있는지 확인 (Safe Delete)
    # 이미 만들어둔 get_reverse_references 함수를 재활용합니다.
    reverse_refs = get_reverse_references(db, form_id, entry_id)
    
    # 참조가 하나라도 있으면 삭제 차단
    if reverse_refs:
        ref_msg = []
        for ref in reverse_refs:
            child_count = len(ref['children'])
            ref_msg.append(f"[{ref['form_title']}]에서 {child_count}건")
        
        err_details = ", ".join(ref_msg)
        flash(f"삭제 불가: 이 데이터를 참조하고 있는 하위 데이터가 있습니다. ({err_details})", "danger")
        return redirect(url_for('list_entries', form_id=form_id))

    # 3. 참조 없음 - 삭제 진행
    try:
        # 관련 히스토리도 같이 삭제할지, 남길지 정책 결정 (여기선 히스토리도 정리)
        db.execute('DELETE FROM history WHERE entry_id = ?', (entry_id,))
        db.execute('DELETE FROM entries WHERE id = ?', (entry_id,))
        db.commit()
        flash("삭제되었습니다.", "success")
    except Exception as e:
        db.rollback()
        flash(f"삭제 중 오류: {e}", "danger")
        
    return redirect(url_for('list_entries', form_id=form_id))

@app.route('/entry/delete_all/<int:form_id>', methods=['POST'])
@login_required
def delete_all_entries(form_id):
    db = get_db()
    try:
        db.execute('DELETE FROM entries WHERE form_id = ?', (form_id,))
        db.commit()
    except Exception as e:
        db.rollback()
    return redirect(url_for('list_entries', form_id=form_id))

# ==========================================
# 7. 대시보드 / 관계도 / 통계 / 관리자
# ==========================================
@app.route('/')
@login_required
def home():
    db = get_db()
    f_cnt = db.execute('SELECT COUNT(*) FROM forms').fetchone()[0]
    e_cnt = db.execute('SELECT COUNT(*) FROM entries').fetchone()[0]
    stats = db.execute('SELECT f.title, COUNT(e.id) as cnt FROM forms f LEFT JOIN entries e ON f.id = e.form_id GROUP BY f.id').fetchall()
    chart_labels = [r['title'] for r in stats]
    chart_data = [r['cnt'] for r in stats]
    recent_rows = db.execute('''SELECT e.created_at, e.data_json, f.title, f.id as form_id FROM entries e JOIN forms f ON e.form_id = f.id ORDER BY e.created_at DESC LIMIT 5''').fetchall()
    recent_list = []
    for r in recent_rows:
        d = safe_json_loads(r['data_json'])
        summary = list(d.values())[0] if d else "내용 없음"
        recent_list.append({"form_title": r['title'], "form_id": r['form_id'], "summary": summary, "created_at": r['created_at']})
    return render_template('home.html', form_count=f_cnt, entry_count=e_cnt, recent_list=recent_list, chart_labels=chart_labels, chart_data=chart_data)

@app.route('/stats')
@login_required
def stats_page():
    db = get_db()
    rows = db.execute('SELECT f.title, COUNT(e.id) as cnt FROM forms f LEFT JOIN entries e ON f.id = e.form_id GROUP BY f.id ORDER BY cnt DESC').fetchall()
    return render_template('stats.html', labels=[r['title'] for r in rows], data=[r['cnt'] for r in rows])

@app.route('/relations')
@login_required
def relation_map():
    """데이터 관계도 시각화"""
    db = get_db()
    forms = db.execute('SELECT id, title, schema_json FROM forms').fetchall()
    
    # 1. 노드 생성
    cnt_rows = db.execute('SELECT form_id, COUNT(*) as cnt FROM entries GROUP BY form_id').fetchall()
    counts = {r['form_id']: r['cnt'] for r in cnt_rows}
    
    nodes = []
    id_map = {}
    for f in forms:
        nodes.append({"id": f['id'], "title": f['title'], "total_count": counts.get(f['id'], 0), "schema": json.loads(f['schema_json'])})
        id_map[f['id']] = f['title']

    # 2. 링크 생성
    links = []
    for f in forms:
        schema = json.loads(f['schema_json'])
        for field in schema:
            if field['type'] == 'relation' and field.get('target_id'):
                tid = int(field['target_id'])
                if tid in id_map:
                    rel_cnt = db.execute(f"SELECT COUNT(*) FROM entries WHERE form_id=? AND json_extract(data_json, '$.{field['key']}') != ''", (f['id'],)).fetchone()[0]
                    links.append({"source": f['id'], "target": tid, "key": field['key'], "label": field['label'], "count": rel_cnt})
    
    return render_template('relations.html', nodes=nodes, links=links)

@app.route('/relation_datas')
@login_required
def relation_datas():
    db = get_db()
    
    # 1. 폼 정보 로딩 (category 컬럼 포함)
    # [중요] category 컬럼이 없으면 에러가 날 수 있으므로, init_db에서 컬럼이 추가되었는지 확인 필요
    # 만약 에러가 난다면 'category' 컬럼이 없는 것이니, SELECT id, title, schema_json FROM forms 로 되돌려야 함
    try:
        forms = db.execute('SELECT id, title, schema_json, category FROM forms').fetchall()
    except:
        # 혹시 컬럼이 없을 경우를 대비한 안전장치
        forms = db.execute('SELECT id, title, schema_json FROM forms').fetchall()
        
    form_map = {f['id']: {'title': f['title'], 'schema': safe_json_loads(f['schema_json']), 'category': f['category'] if 'category' in f.keys() else 'general'} for f in forms}
    
    entries = db.execute('SELECT id, form_id, data_json FROM entries').fetchall()
    nodes, links = [], []
    entry_ids = set(e['id'] for e in entries)

    # 요약 정보 생성 헬퍼 (list_network와 로직 공유)
    def get_summary(f_id, data_dict):
        if not data_dict: return ""
        if f_id not in form_map: return ""
        schema = form_map[f_id]['schema']
        summary_lines = []
        count = 0
        for field in schema:
            key = field['key']
            if field['type'] == 'file': continue
            val = data_dict.get(key)
            if not val: continue
            
            display_val = val
            if field['type'] == 'relation':
                display_val = _resolve_relation_labels(db, val)
            
            # 텍스트가 너무 길면 자르기
            str_val = str(display_val)
            if len(str_val) > 20: str_val = str_val[:20] + "..."
            
            summary_lines.append(f"<span class='text-muted small'>{field['label']}:</span> <strong>{str_val}</strong>")
            count += 1
            if count >= 4: break
        return "<br>".join(summary_lines)

    for e in entries:
        f_id = e['form_id']
        if f_id not in form_map: continue
        
        data = safe_json_loads(e['data_json'])
        label = list(data.values())[0] if data else f"ID:{e['id']}"
        if len(str(label)) > 15: label = str(label)[:12] + ".."
        
        # 요약 정보 생성
        summary = get_summary(f_id, data)

        nodes.append({
            "id": e['id'], 
            "group": f_id, 
            "label": label, 
            "attributes": summary,
            "is_primary": True # 전체 보기이므로 모두 잘 보이게 처리
        })
        
        schema = form_map[f_id]['schema']
        for field in schema:
            if field['type'] == 'relation' and field.get('target_id'):
                target_val = data.get(field['key'])
                if target_val:
                    targets = target_val if isinstance(target_val, list) else [target_val]
                    for t_id in targets:
                        try:
                            if int(t_id) in entry_ids:
                                links.append({"source": e['id'], "target": int(t_id)})
                        except: pass
                        
    return render_template('relation_datas.html', nodes=nodes, links=links, form_map=form_map)

@app.route('/list/network/<int:form_id>')
@login_required
def list_network(form_id):
    db = get_db()
    
    # 1. 현재 폼 정보 및 전체 폼 스키마 로딩
    target_form = db.execute('SELECT * FROM forms WHERE id = ?', (form_id,)).fetchone()
    if not target_form: return "폼 없음", 404
    
    all_forms = db.execute('SELECT id, title, schema_json, category FROM forms').fetchall()
    form_map = {f['id']: {'title': f['title'], 'schema': safe_json_loads(f['schema_json']), 'category': f['category']} for f in all_forms}
    
    # 2. 메인 노드(현재 폼의 데이터들) 생성
    primary_rows = db.execute('SELECT id, form_id, data_json FROM entries WHERE form_id = ?', (form_id,)).fetchall()
    nodes, links = [], []
    added_node_ids = set()
    primary_ids = set()

    # [NEW] 데이터 요약 텍스트 생성 헬퍼
    def get_summary(f_id, data_dict):
        if not data_dict: return ""
        schema = form_map[f_id]['schema']
        summary_lines = []
        count = 0
        for field in schema:
            key = field['key']
            # 파일은 제외, 너무 긴 텍스트는 제외 가능
            if field['type'] == 'file': continue
            
            val = data_dict.get(key)
            if not val: continue
            
            # 관계형 데이터면 ID -> 이름 변환
            display_val = val
            if field['type'] == 'relation':
                display_val = _resolve_relation_labels(db, val)
            
            # "라벨: 값" 형태 (예: 부서: 개발팀)
            summary_lines.append(f"<span class='text-muted small'>{field['label']}:</span> <strong>{display_val}</strong>")
            count += 1
            if count >= 4: break # 최대 4개 필드까지만 표시
        
        return "<br>".join(summary_lines)

    # [수정] 노드 추가 헬퍼 (data_dict 인자 추가)
    def add_node(entry_id, f_id, label, is_primary=False, data_dict=None):
        if entry_id not in added_node_ids:
            # 요약 정보 생성
            summary = get_summary(f_id, data_dict) if data_dict else ""
            
            nodes.append({
                "id": entry_id, 
                "label": label, 
                "group": f_id, 
                "form_title": form_map[f_id]['title'], 
                "is_primary": is_primary,
                "attributes": summary # [NEW] 팝업용 속성 정보
            })
            added_node_ids.add(entry_id)

    # 메인 노드 등록
    for row in primary_rows:
        d = safe_json_loads(row['data_json'])
        lbl = list(d.values())[0] if d else f"ID:{row['id']}"
        add_node(row['id'], form_id, lbl, is_primary=True, data_dict=d)
        primary_ids.add(row['id'])
    
    # 3. 전체 데이터를 순회하며 연결 고리 찾기
    all_entries = db.execute('SELECT id, form_id, data_json FROM entries').fetchall()
    
    for row in all_entries:
        curr_id = row['id']
        curr_fid = row['form_id']
        curr_data = safe_json_loads(row['data_json'])
        curr_schema = form_map[curr_fid]['schema']
        
        # (A) 정방향 (Outbound)
        if curr_id in primary_ids:
            for field in curr_schema:
                if field['type'] == 'relation' and field.get('target_id'):
                    val = curr_data.get(field['key'])
                    if val:
                        targets = val if isinstance(val, list) else [val]
                        for tid in targets:
                            try:
                                tid = int(tid)
                                t_row = db.execute('SELECT form_id, data_json FROM entries WHERE id = ?', (tid,)).fetchone()
                                if t_row:
                                    t_d = safe_json_loads(t_row['data_json'])
                                    t_lbl = list(t_d.values())[0] if t_d else str(tid)
                                    
                                    add_node(tid, t_row['form_id'], t_lbl, is_primary=False, data_dict=t_d) # [수정] data 전달
                                    links.append({"source": curr_id, "target": tid, "type": "out"})
                            except: pass

        # (B) 역방향 (Inbound)
        else:
            for field in curr_schema:
                if field['type'] == 'relation' and str(field.get('target_id')) == str(form_id):
                    val = curr_data.get(field['key'])
                    if val:
                        targets = val if isinstance(val, list) else [val]
                        for tid in targets:
                            try:
                                tid = int(tid)
                                if tid in primary_ids:
                                    curr_lbl = list(curr_data.values())[0] if curr_data else str(curr_id)
                                    add_node(curr_id, curr_fid, curr_lbl, is_primary=False, data_dict=curr_data) # [수정] data 전달
                                    links.append({"source": curr_id, "target": tid, "type": "in"}) 
                            except: pass

    return render_template('list_network.html', nodes=nodes, links=links, current_form=target_form, forms=all_forms, form_map=form_map)

@app.route('/entry/network/<int:entry_id>')
@login_required
def entry_network(entry_id):
    db = get_db()
    center = db.execute('SELECT * FROM entries WHERE id = ?', (entry_id,)).fetchone()
    if not center: return "데이터 없음", 404
    center_data = safe_json_loads(center['data_json'])
    center_label = list(center_data.values())[0] if center_data else f"ID:{entry_id}"
    forms = db.execute('SELECT id, title, schema_json FROM forms').fetchall()
    form_map = {f['id']: {'title': f['title'], 'schema': safe_json_loads(f['schema_json'])} for f in forms}
    nodes = [{"id": entry_id, "label": center_label, "group": 0, "form_title": form_map[center['form_id']]['title'], "is_center": True}]
    links = []
    
    my_schema = form_map[center['form_id']]['schema']
    for field in my_schema:
        if field['type'] == 'relation' and field.get('target_id'):
            val = center_data.get(field['key'])
            if val:
                targets = val if isinstance(val, list) else [val]
                for tid in targets:
                    try:
                        tr = db.execute('SELECT form_id, data_json FROM entries WHERE id = ?', (tid,)).fetchone()
                        if tr:
                            td = safe_json_loads(tr['data_json'])
                            t_lbl = list(td.values())[0] if td else str(tid)
                            nodes.append({"id": int(tid), "label": t_lbl, "group": tr['form_id'], "form_title": form_map[tr['form_id']]['title'], "is_center": False})
                            links.append({"source": entry_id, "target": int(tid)})
                    except: pass
    return render_template('entry_network.html', nodes=nodes, links=links, center_label=center_label)

# [NEW] 관계 데이터 상세 조회 API (엣지 클릭 시 호출됨)
@app.route('/api/relation_data/<int:form_id>/<field_key>')
@login_required
def api_relation_data(form_id, field_key):
    db = get_db()
    
    # 1. Source 폼 정보 가져오기
    src_form = db.execute('SELECT title, schema_json FROM forms WHERE id=?', (form_id,)).fetchone()
    if not src_form: return jsonify({'error': 'Form not found'}), 404
    
    src_schema = json.loads(src_form['schema_json'])
    
    # 2. 해당 필드(key)가 참조하는 Target 폼 ID 찾기
    target_id = None
    for field in src_schema:
        if field['key'] == field_key:
            target_id = int(field['target_id'])
            break
            
    if not target_id: return jsonify({'error': 'Invalid relation key'}), 400
    
    # 3. Target 폼 정보 가져오기
    tgt_form = db.execute('SELECT title, schema_json FROM forms WHERE id=?', (target_id,)).fetchone()
    tgt_schema = json.loads(tgt_form['schema_json'])

    # 4. 데이터 표시 헬퍼 (첫 번째 필드 값을 대표 값으로 사용)
    def get_display_val(schema, data):
        if not data: return "-"
        # 첫 번째 키를 찾아서 값 반환
        first_key = schema[0]['key']
        return str(data.get(first_key, ''))

    # 5. 연결된 데이터 찾기
    rows = []
    # Source 데이터 전체 조회 (데이터가 많으면 SQL에서 필터링하는 것이 좋음)
    entries = db.execute('SELECT id, data_json FROM entries WHERE form_id=?', (form_id,)).fetchall()
    
    for r in entries:
        d = json.loads(r['data_json'])
        val = d.get(field_key)
        
        # 값이 있는 경우 (연결됨)
        if val:
            # 다중 선택(List)일 수도 있고 단일 선택일 수도 있음
            t_ids = val if isinstance(val, list) else [val]
            
            src_val = get_display_val(src_schema, d)
            
            for tid in t_ids:
                # Target 데이터 조회
                t_row = db.execute('SELECT id, data_json FROM entries WHERE id=?', (tid,)).fetchone()
                
                t_val = "삭제된 데이터"
                found = False
                
                if t_row:
                    t_d = json.loads(t_row['data_json'])
                    t_val = get_display_val(tgt_schema, t_d)
                    found = True
                
                rows.append({
                    "source": { "id": r['id'], "values": [src_val] },
                    "target": { "id": tid, "values": [t_val], "found": found }
                })

    return jsonify({
        "source_title": src_form['title'],
        "target_title": tgt_form['title'],
        "rows": rows
    })
    
    
# 1. 시스템 맵 (Edge에 데이터 개수 포함)
@app.route('/system_map')
@login_required
def system_map():
    db = get_db()
    forms = db.execute('SELECT id, title, schema_json, category FROM forms').fetchall()
    
    nodes = []
    links = []
    
    for f in forms:
        # 노드 정보 생성
        nodes.append({
            "id": f['id'],
            "label": f['title'], # 줄바꿈 처리는 JS에서 함
            "group": f['category'] if 'category' in f.keys() else 'general',
            "is_code": (f['category'] == 'standard') if 'category' in f.keys() else False
        })
        
        # 링크 생성 (데이터 개수 카운트 포함)
        schema = safe_json_loads(f['schema_json'])
        for field in schema:
            if field['type'] == 'relation' and field.get('target_id'):
                try:
                    target_id = int(field['target_id'])
                    target_key = field['key']
                    
                    # [핵심] 실제로 연결된 데이터 개수 세기 (JSON 파싱)
                    rows = db.execute('SELECT data_json FROM entries WHERE form_id = ?', (f['id'],)).fetchall()
                    count = 0
                    for r in rows:
                        d = safe_json_loads(r['data_json'])
                        val = d.get(target_key)
                        if val:
                            if isinstance(val, list) and len(val) > 0: count += 1
                            elif not isinstance(val, list): count += 1

                    if count > 0: # 데이터가 있는 경우에만 연결선 표시
                        links.append({
                            "source": f['id'],
                            "target": target_id,
                            "label": f"{field['label']} ({count})", # 라벨에 개수 표시
                            "count": count,
                            "field_key": target_key
                        })
                except: pass

    return render_template('system_map.html', nodes=nodes, links=links)

# 2. [NEW] 엣지 상세 관계도 (클릭 시 모달 내용)
@app.route('/network/edge/<int:source_form_id>/<int:target_form_id>/<field_key>')
@login_required
def edge_network(source_form_id, target_form_id, field_key):
    db = get_db()
    
    src_form = db.execute('SELECT title FROM forms WHERE id=?', (source_form_id,)).fetchone()
    tgt_form = db.execute('SELECT title FROM forms WHERE id=?', (target_form_id,)).fetchone()
    
    # Source 데이터 가져오기
    src_entries = db.execute('SELECT id, data_json FROM entries WHERE form_id=?', (source_form_id,)).fetchall()
    
    nodes = []
    links = []
    added_ids = set()
    
    def add_n(eid, label, group, is_src):
        if eid not in added_ids:
            nodes.append({
                "id": eid, 
                "label": str(label)[:10], 
                "group": group, # 0: Source, 1: Target
                "level": 0 if is_src else 1 
            })
            added_ids.add(eid)

    # 연결된 데이터만 필터링
    for row in src_entries:
        d = safe_json_loads(row['data_json'])
        val = d.get(field_key)
        
        if val:
            src_lbl = list(d.values())[0] if d else f"ID:{row['id']}"
            target_ids = val if isinstance(val, list) else [val]
            
            valid_targets = []
            for tid in target_ids:
                try:
                    t_row = db.execute('SELECT id, data_json FROM entries WHERE id=?', (tid,)).fetchone()
                    if t_row:
                        t_d = safe_json_loads(t_row['data_json'])
                        t_lbl = list(t_d.values())[0] if t_d else f"ID:{tid}"
                        add_n(tid, t_lbl, 1, False) # Target
                        links.append({"from": row['id'], "to": tid})
                        valid_targets.append(tid)
                except: pass
            
            if valid_targets:
                add_n(row['id'], src_lbl, 0, True) # Source

    return render_template('edge_network.html', 
                           nodes=nodes, links=links, 
                           src_title=src_form['title'], tgt_title=tgt_form['title'])
    
@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin_page():
    # 1. 관리자 권한 체크
    if not current_user.is_admin:
        flash("관리자 권한이 필요합니다.", "danger")
        return redirect(url_for('home'))
    
    db = get_db()
    
    # 변수 초기화
    query_result = None
    query_error = None
    sql_query = ""
    affected_rows = 0
    
    # 2. SQL 쿼리 실행 요청 처리 (POST)
    if request.method == 'POST':
        sql_query = request.form.get('sql_query', '')
        if sql_query.strip():
            try:
                # 쿼리 실행
                cursor = db.execute(sql_query)
                
                if sql_query.strip().upper().startswith("SELECT"):
                    # SELECT 문: 결과 데이터 가져오기
                    rows = cursor.fetchall()
                    # 컬럼명 추출
                    cols = [desc[0] for desc in cursor.description] if cursor.description else []
                    query_result = {"type": "select", "cols": cols, "rows": rows}
                else:
                    # INSERT, UPDATE, DELETE 등: 변경사항 반영
                    db.commit()
                    affected_rows = cursor.rowcount
                    query_result = {"type": "action", "message": f"실행 완료. (영향받은 행: {affected_rows}건)"}
                    
            except Exception as e:
                query_error = f"SQL 오류: {str(e)}"
                db.rollback()

    # 3. 기존 테이블 조회 기능 (GET 파라미터)
    target_table = request.args.get('table')
    # sqlite_sequence 같은 내부 테이블 제외하고 목록 가져오기
    tables = [t['name'] for t in db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name").fetchall()]
    
    table_data = None
    table_cols = []
    
    if target_table and target_table in tables:
        try:
            cur = db.execute(f"SELECT * FROM {target_table} LIMIT 100") # 너무 많으면 끊어서 보여줌
            table_cols = [desc[0] for desc in cur.description]
            table_data = cur.fetchall()
        except: pass

    return render_template('admin.html', 
                           tables=tables, 
                           current_table=target_table, 
                           columns=table_cols, 
                           data=table_data,
                           # 쿼리 실행 관련 변수 전달
                           sql_query=sql_query,
                           query_result=query_result,
                           query_error=query_error)

@app.route('/admin/delete_user/<user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if not current_user.is_admin: return "권한 없음", 403
    if user_id == 'admin': return redirect(url_for('admin_page'))
    db = get_db()
    db.execute('DELETE FROM users WHERE id = ?', (user_id,))
    db.commit()
    return redirect(url_for('admin_page'))

# ==========================================
# 8. 엑셀 및 기타 API
# ==========================================
@app.route('/excel/template/<int:form_id>')
@login_required
def excel_download_template(form_id):
    db = get_db()
    form = db.execute('SELECT title, schema_json FROM forms WHERE id = ?', (form_id,)).fetchone()
    schema = safe_json_loads(form['schema_json'])
    headers = [f['label'] for f in schema]
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        pd.DataFrame(columns=headers).to_excel(writer, index=False, sheet_name='입력서식')
    output.seek(0)
    return send_file(output, as_attachment=True, download_name=f"{form['title']}_입력서식.xlsx")

# [업그레이드] 엑셀 업로드 (기존 데이터 수정 + 신규 등록 + 히스토리 기록)
@app.route('/excel/upload/<int:form_id>', methods=['POST'])
@login_required
def excel_upload_entries(form_id):
    if 'file' not in request.files: return "파일 없음", 400
    file = request.files['file']
    if not file.filename: return "파일 선택 안됨", 400

    try:
        db = get_db()
        form = db.execute('SELECT schema_json FROM forms WHERE id = ?', (form_id,)).fetchone()
        schema = safe_json_loads(form['schema_json'])
        # 엑셀 헤더(Label) -> DB 키(Key) 매핑
        label_to_key = {f['label']: f['key'] for f in schema}
        
        # 데이터프레임 로드 (문자열로 변환하여 에러 방지)
        df = pd.read_excel(file).fillna('')
        
        updated_count = 0
        created_count = 0
        
        for _, row in df.iterrows():
            data = {}
            # 1. 엑셀 데이터를 스키마에 맞춰 딕셔너리로 변환
            for label, val in row.items():
                if label in label_to_key:
                    # 날짜나 숫자도 문자열로 통일해서 저장 (필요시 타입 변환 로직 추가 가능)
                    data[label_to_key[label]] = str(val)

            # 2. ID 컬럼 존재 여부 확인 (수정 vs 생성 판단)
            entry_id = None
            if 'ID' in row and str(row['ID']).strip():
                try:
                    chk_id = int(row['ID'])
                    # 해당 ID가 실제로 이 폼의 데이터인지 확인
                    exists = db.execute('SELECT 1 FROM entries WHERE id = ? AND form_id = ?', (chk_id, form_id)).fetchone()
                    if exists: entry_id = chk_id
                except: pass

            if entry_id:
                # [수정 모드]
                # 기존 데이터 가져오기 (Diff 생성을 위해)
                cur_row = db.execute('SELECT data_json FROM entries WHERE id = ?', (entry_id,)).fetchone()
                old_data = safe_json_loads(cur_row['data_json'])
                
                # 변경사항 감지
                diff = get_diff_text(db, schema, old_data, data)
                
                if diff: # 변경된 내용이 있을 때만 업데이트
                    db.execute('UPDATE entries SET data_json = ? WHERE id = ?', (json.dumps(data, ensure_ascii=False), entry_id))
                    log_history(db, entry_id, "엑셀수정", diff)
                    updated_count += 1
            else:
                # [생성 모드]
                cursor = db.execute('INSERT INTO entries (form_id, data_json) VALUES (?, ?)', (form_id, json.dumps(data, ensure_ascii=False)))
                log_history(db, cursor.lastrowid, "엑셀생성", "일괄 업로드")
                created_count += 1

        db.commit()
        flash(f"업로드 완료: 신규 {created_count}건, 수정 {updated_count}건", "success")
        return redirect(url_for('list_entries', form_id=form_id))
        
    except Exception as e:
        db.rollback()
        return f"업로드 처리 중 오류 발생: {str(e)}"

@app.route('/excel/download/<int:form_id>')
@login_required
def excel_download_entries(form_id):
    db = get_db()
    
    # 1. 현재 폼 정보 가져오기
    form = db.execute('SELECT title, schema_json FROM forms WHERE id = ?', (form_id,)).fetchone()
    if not form: return "폼을 찾을 수 없습니다.", 404
    
    schema = safe_json_loads(form['schema_json'])
    
    # ---------------------------------------------------------
    # [A] 정방향(Outbound) 데이터 준비 (ID -> Label 변환용)
    # ---------------------------------------------------------
    lookup_map = {}
    for field in schema:
        if field['type'] == 'relation' and field.get('target_id'):
            target_rows = db.execute('SELECT id, data_json FROM entries WHERE form_id = ?', (field['target_id'],)).fetchall()
            id_to_label = {}
            for tr in target_rows:
                td = safe_json_loads(tr['data_json'])
                label = list(td.values())[0] if td else str(tr['id'])
                id_to_label[str(tr['id'])] = label
            lookup_map[field['key']] = id_to_label

    # ---------------------------------------------------------
    # [B] 역방향(Inbound/하위) 데이터 준비 [NEW]
    # ---------------------------------------------------------
    # 구조: reverse_map[내ID]["(참조) 하위폼이름"] = ["하위데이터1", "하위데이터2"]
    reverse_map = {} 
    
    # 1. 전체 폼을 뒤져서 나(form_id)를 참조하는 필드가 있는지 확인
    all_forms = db.execute('SELECT id, title, schema_json FROM forms').fetchall()
    
    # 나를 참조하는 필드 정보: (폼ID, 폼제목, 필드키, 필드제목)
    referencing_fields = []
    
    for other_form in all_forms:
        if other_form['id'] == form_id: continue # 나는 제외
        
        try: other_schema = json.loads(other_form['schema_json'])
        except: continue
        
        for f in other_schema:
            # 타겟이 '나'인 경우
            if f['type'] == 'relation' and str(f.get('target_id')) == str(form_id):
                referencing_fields.append({
                    'form_id': other_form['id'],
                    'form_title': other_form['title'],
                    'field_key': f['key'],
                    'field_label': f['label']
                })

    # 2. 해당 필드를 가진 데이터들을 싹 가져와서 매핑 (성능 최적화: 한방 쿼리 아님 루프)
    for ref_info in referencing_fields:
        # 하위 폼의 모든 데이터 가져오기 (데이터가 많으면 여기서 필터링 최적화 가능)
        child_rows = db.execute('SELECT id, data_json FROM entries WHERE form_id = ?', (ref_info['form_id'],)).fetchall()
        
        col_name = f"(참조) {ref_info['form_title']}"
        
        for row in child_rows:
            d = safe_json_loads(row['data_json'])
            target_val = d.get(ref_info['field_key']) # 부모(나)를 가리키는 값
            child_label = list(d.values())[0] if d else f"ID:{row['id']}" # 하위 데이터 이름
            
            # 값이 없으면 패스
            if not target_val: continue
            
            # 타겟 값이 리스트(["1", "2"])인지 단일값("1")인지 확인
            target_ids = target_val if isinstance(target_val, list) else [target_val]
            
            # 내 ID(parent_id)별로 그룹핑
            for parent_id in target_ids:
                pid = str(parent_id)
                if pid not in reverse_map: reverse_map[pid] = {}
                if col_name not in reverse_map[pid]: reverse_map[pid][col_name] = []
                
                reverse_map[pid][col_name].append(child_label)

    # ---------------------------------------------------------
    # [C] 엑셀 데이터 조립
    # ---------------------------------------------------------
    rows = db.execute('SELECT id, data_json, created_at FROM entries WHERE form_id = ? ORDER BY created_at DESC', (form_id,)).fetchall()
    data_list = []
    
    # 동적으로 추가될 하위 참조 컬럼명들 수집 (헤더 정렬용)
    reverse_headers = sorted(list(set(k for v in reverse_map.values() for k in v.keys())))

    for r in rows:
        d = safe_json_loads(r['data_json'])
        
        # 1. 기본 정보
        item = {'ID': r['id'], '등록일': r['created_at'][:16]}
        
        # 2. 내 필드 (정방향 변환 포함)
        for field in schema:
            key = field['key']
            val = d.get(key, '')
            
            if field['type'] == 'relation' and key in lookup_map:
                if isinstance(val, list): 
                    labels = [lookup_map[key].get(str(v), v) for v in val]
                    item[field['label']] = ", ".join(labels)
                else:
                    item[field['label']] = lookup_map[key].get(str(val), val)
            else:
                item[field['label']] = val
        
        # 3. [NEW] 하위 참조 데이터 채우기
        my_id = str(r['id'])
        for header in reverse_headers:
            # 내 ID에 해당하는 하위 데이터가 있으면 콤마로 연결, 없으면 빈칸
            if my_id in reverse_map and header in reverse_map[my_id]:
                item[header] = ", ".join(reverse_map[my_id][header])
            else:
                item[header] = ""
                
        data_list.append(item)

    # ---------------------------------------------------------
    # [D] 엑셀 파일 생성
    # ---------------------------------------------------------
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        pd.DataFrame(data_list).to_excel(writer, index=False, sheet_name='데이터목록')
        
        # 컬럼 너비 자동 조정
        worksheet = writer.sheets['데이터목록']
        for column_cells in worksheet.columns:
            length = max(len(str(cell.value)) for cell in column_cells)
            worksheet.column_dimensions[column_cells[0].column_letter].width = min(length + 5, 50)

    output.seek(0)
    return send_file(output, as_attachment=True, download_name=f"{form['title']}_데이터목록.xlsx")

@app.route('/api/preview/<int:form_id>')
@login_required
def api_preview_entries(form_id):
    db = get_db()
    form = db.execute('SELECT schema_json FROM forms WHERE id = ?', (form_id,)).fetchone()
    if not form: return jsonify({'error': 'Not found'}), 404
    schema = safe_json_loads(form['schema_json'])
    keys = [f['key'] for f in schema if f['type'] not in ['file', 'relation']][:3]
    labels = [f['label'] for f in schema if f['key'] in keys]
    rows = db.execute('SELECT id, data_json, created_at FROM entries WHERE form_id=? ORDER BY id DESC LIMIT 5', (form_id,)).fetchall()
    result = []
    for r in rows:
        d = safe_json_loads(r['data_json'])
        vals = [str(d.get(k, '-'))[:10] for k in keys]
        result.append({'id': r['id'], 'created_at': r['created_at'][:10], 'values': vals})
    return jsonify({'headers': labels, 'rows': result})

# [안정화] 에러 핸들러
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500

if __name__ == '__main__':
    init_db()
    app.run(debug=True, host='0.0.0.0', port=5000)
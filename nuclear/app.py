from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file
import sqlite3
import pandas as pd
import os
import re
import io
from datetime import datetime
from functools import wraps

app = Flask(__name__)
app.secret_key = 'nuclear_safety_secret_key'  # 세션 암호화 키

# === 설정 ===
DB_PATH = 'nuclear.db'
ADMIN_ID = 'admin'
ADMIN_PW = 'dnjswkfur'  # 실제 운영시 복잡하게 변경

# === DB 초기화 함수 ===

# app.py 의 init_db 함수 수정

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    # 1. 명단 세트 관리 (인사발령 파일 단위 그룹)
    c.execute('''CREATE TABLE IF NOT EXISTS personnel_sets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        set_name TEXT,
        created_date TEXT
    )''')
    
    # 2. 방재요원 명단 (최종 스키마 적용)
    c.execute('''CREATE TABLE IF NOT EXISTS personnel (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        set_id INTEGER,
        dept TEXT,              -- 부서
        name TEXT,              -- 이름
        email TEXT,
        position TEXT,          -- 직급
        emergency_role TEXT,    -- 비상시 직위 (종합조정반 등)
        phone TEXT,             -- 연락처
        target_type TEXT,       -- 교육대상 유형 (신규/보수 - 명단 등록 시점 기준)
        designation_date TEXT,  -- 방재요원 지정일자
        FOREIGN KEY(set_id) REFERENCES personnel_sets(id)
    )''')
    
    # 3. 교육 이수 기록 (최종 스키마 적용)
    c.execute('''CREATE TABLE IF NOT EXISTS training_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        dept TEXT,
        phone TEXT,
        email TEXT,
        training_date TEXT,     -- 교육일자 (YYYY.MM.DD)
        training_year INTEGER,  -- 교육연도 (2025 등 숫자형)
        training_type TEXT,     -- 교육구분 (신규/보수)
        hours INTEGER,          -- 인정시간 (18/8)
        safety_status TEXT      -- 재난안전교육 이수 여부 (O/X)
    )''')

    # 4. 부서 정렬 순서 관리 (마스터 테이블)
    c.execute('''CREATE TABLE IF NOT EXISTS departments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        dept_name TEXT UNIQUE,      -- 부서명 (중복 불가)
        sort_order INTEGER DEFAULT 999 -- 정렬 순서 (기본값 999)
    )''')
        
    conn.commit()
    conn.close()


init_db()

# === 로그인 데코레이터 ===
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# === 라우트 (페이지) ===

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user_id = request.form['id']
        user_pw = request.form['pw']
        if user_id == ADMIN_ID and user_pw == ADMIN_PW:
            session['user'] = user_id
            return redirect(url_for('dashboard'))
        else:
            flash('아이디 또는 비밀번호가 틀렸습니다.')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))

@app.route('/')
@login_required
def dashboard():
    conn = sqlite3.connect(DB_PATH)
    # 최신 명단 세트 가져오기
    sets = conn.execute("SELECT id, set_name FROM personnel_sets ORDER BY id DESC").fetchall()
    
    selected_set_id = request.args.get('set_id')
    current_set_name = ""
    
    if not sets:
        return render_template('dashboard.html', no_data=True)
    
    if not selected_set_id:
        selected_set_id = sets[0][0] # 기본값: 가장 최신
        current_set_name = sets[0][1]
    else:
        selected_set_id = int(selected_set_id)
        for s in sets:
            if s[0] == selected_set_id: current_set_name = s[1]

    # 통계 쿼리 (V3 로직 동일)
    year = datetime.now().year
    query = f"""
        SELECT 
            p.dept, p.name, p.phone,
            t.id, t.safety_status
        FROM personnel p
        LEFT JOIN training_history t 
            ON p.name = t.name 
            AND ((length(p.phone)>5 AND p.phone = t.phone) OR (p.dept = t.dept))
            AND t.training_year = {year}
        WHERE p.set_id = ?
        GROUP BY p.id
    """
    df = pd.read_sql_query(query, conn, params=(selected_set_id,))
    conn.close()

    # 데이터 가공
    total = len(df)
    completed = df['id'].notnull().sum()
    safety_cnt = df[df['safety_status'] == 'O'].shape[0]
    rate = round(completed / total * 100, 1) if total > 0 else 0
    
    # 부서별 통계
    dept_stats = df.copy()
    dept_stats['is_completed'] = dept_stats['id'].notnull()
    dept_group = dept_stats.groupby('dept')['is_completed'].mean() * 100
    dept_group = dept_group.sort_values().head(10) # 하위 10개
    
    return render_template('dashboard.html', 
                           sets=sets, current_set_id=selected_set_id, current_set_name=current_set_name,
                           total=total, completed=completed, safety_cnt=safety_cnt, rate=rate,
                           dept_labels=dept_group.index.tolist(), dept_values=dept_group.values.tolist(),
                           no_data=False)

@app.route('/radiation')
@login_required
def radiation():
    return render_template('working.html', title='📡 환경방사선 감시')

@app.route('/drills')
@login_required
def drills():
    return render_template('working.html', title='📢 훈련 관리')

@app.route('/committee')
@login_required
def committee():
    return render_template('working.html', title='🤝 위원회 관리')

@app.route('/equipment')
@login_required
def equipment():
    return render_template('working.html', title='🧰 방재장비 관리')

@app.route('/medicine')
@login_required
def medicine():
    return render_template('working.html', title='💊 갑상샘방호약품 관리')

@app.route('/relief')
@login_required
def relief():
    return render_template('working.html', title='⛺ 구호소 관리')

@app.route('/assembly')
@login_required
def assembly():
    return render_template('working.html', title='📍 집결지 관리')

# === [핵심] 공통 로직 함수 (화면조회 & 엑셀다운로드에서 같이 사용) ===
def get_personnel_data(set_id, target_year):
    conn = sqlite3.connect(DB_PATH)
    
    # 1. 인사 정보 조회
    query = """
        SELECT p.id as p_id, p.*, d.sort_order
        FROM personnel p
        LEFT JOIN departments d 
          ON REPLACE(p.dept, ' ', '') = REPLACE(d.dept_name, ' ', '')
        WHERE p.set_id = ? 
        ORDER BY 
            COALESCE(d.sort_order, 9999) ASC,
            p.dept ASC,
            p.name ASC
    """
    df_personnel = pd.read_sql_query(query, conn, params=(set_id,))
    
    # 2. 교육 이력 조회
    df_history = pd.read_sql_query(
        "SELECT * FROM training_history ORDER BY training_date DESC", 
        conn
    )
    conn.close()

    # [데이터 전처리]
    if 'training_year' not in df_history.columns:
        def extract_year(date_str):
            try: return int(str(date_str).replace('-', '.').strip().split('.')[0])
            except: return datetime.now().year
        df_history['training_year'] = df_history['training_date'].apply(extract_year)

    if 'hours' not in df_history.columns: df_history['hours'] = 8
    if 'safety_status' not in df_history.columns: df_history['safety_status'] = ''
    
    # 이메일 전처리 (공백 제거 및 문자열 변환)
    df_personnel['email'] = df_personnel['email'].fillna('').astype(str).str.strip()
    df_history['email'] = df_history['email'].fillna('').astype(str).str.strip()

    result_rows = []
    today = datetime.now().date()

    for i, row in df_personnel.iterrows():
        email = row['email']
        
        # === [1] 이력 매칭 (ONLY 이메일 엄격 모드) ===
        my_history = pd.DataFrame()
        
        # 이메일이 있고, 'nan'이 아닐 때만 매칭 시도
        if email and len(email) > 2 and email.lower() != 'nan':
            match_email = df_history[df_history['email'] == email]
            if not match_email.empty:
                my_history = match_email.copy()

        # === [2] 교육구분 판별 (최종 솔루션: 이력 있으면 무조건 보수) ===
        edu_type = "신규" # 기본값

        # 지정일자, 연도 상관없이 과거 교육 이력이 하나라도 매칭되었다면?
        # -> "경력직"으로 인정하여 '보수' 처리
        if not my_history.empty:
             edu_type = "보수"

        # === [3] 이수 상태 확인 ===
        status_text = "미이수"
        status_val = "미이수"
        training_year = None
        hours = None
        safety = ""
        last_date = ""

        if not my_history.empty:
            my_history['training_year'] = pd.to_numeric(my_history['training_year'], errors='coerce').fillna(0).astype(int)
            this_year_hist = my_history[my_history['training_year'] == target_year]
            
            if not this_year_hist.empty:
                top = this_year_hist.iloc[0]
                status_text = f"이수({top['training_year']})"
                status_val = "이수"
                training_year = top['training_year']
                hours = top['hours']
                safety = top['safety_status']
                last_date = top['training_date']
            else:
                top = my_history.iloc[0] # 가장 최근 기록
                status_text = f"이수({top['training_year']})"
                status_val = "미이수" 

        # 6개월 이내 신규 지정자 예외 처리
        d_date = pd.to_datetime(row['designation_date'], errors='coerce')
        if status_val == "미이수" and pd.notnull(d_date):
            try:
                d_date_val = d_date.date() if hasattr(d_date, 'date') else d_date
                diff = (today - d_date_val).days
                if 0 <= diff <= 180:
                    status_val = "6개월 이내"
                    status_text = "6개월이내"
            except: pass

        result_rows.append({
            'id': row['p_id'],
            'dept': row['dept'],
            'position': row['position'],
            'name': row['name'],
            'phone': row['phone'],
            'email': email,
            'emergency_role': row['emergency_role'],
            'designation_date': row['designation_date'],
            'target_type': row['target_type'],
            'edu_type_calc': edu_type,
            'status': status_val,
            'status_text': status_text,
            'hours': hours,
            'safety_status': safety,
            'training_date': last_date,
            'training_year': training_year
        })
        
    return result_rows

# === 1. 목록 조회 라우트 ===
@app.route('/personnel_list')
@login_required
def personnel_list():
    conn = sqlite3.connect(DB_PATH)
    sets = conn.execute("SELECT id, set_name FROM personnel_sets ORDER BY id DESC").fetchall()
    conn.close()
    
    selected_set_id = request.args.get('set_id')
    if sets and not selected_set_id: selected_set_id = sets[0][0]
    
    current_year = datetime.now().year
    target_year = request.args.get('target_year')
    if not target_year: target_year = current_year
    else: target_year = int(target_year)
    
    year_list = list(range(current_year, 2014, -1))
    
    rows = []
    stats = {'total': 0, 'completed': 0, 'rate': 0.0, 'uncompleted': 0}
    
    if selected_set_id:
        # 공통 함수 호출
        rows = get_personnel_data(selected_set_id, target_year)
        
        # [신규] 통계 계산 로직
        total_cnt = len(rows)
        completed_cnt = len([r for r in rows if r['status'] == '이수'])
        
        if total_cnt > 0:
            rate = round((completed_cnt / total_cnt) * 100, 1)
        else:
            rate = 0.0
            
        # 신규/보수 인원 카운트
        new_cnt = len([r for r in rows if r['edu_type_calc'] == '신규'])
        refresher_cnt = len([r for r in rows if r['edu_type_calc'] == '보수'])
            
        stats = {
            'total': total_cnt,
            'completed': completed_cnt,
            'uncompleted': total_cnt - completed_cnt,
            'rate': rate,
            'new': new_cnt,           # 신규 인원
            'refresher': refresher_cnt # 보수 인원
        }
        
    return render_template('personnel_list.html', 
                           sets=sets, 
                           current_set_id=int(selected_set_id) if selected_set_id else 0,
                           years=year_list, target_year=target_year, rows=rows, stats=stats)
                           
@app.route('/api/personnel/<int:p_id>', methods=['GET'])
@login_required
def get_personnel_detail(p_id):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    
    # 1. 인적사항 조회
    c.execute("SELECT * FROM personnel WHERE id = ?", (p_id,))
    row = c.fetchone()
    if not row:
        return {'error': 'Not found'}, 404
    person = dict(row)
    
    # 2. 교육 이력 조회 (조건 완화: 이름만 같으면 전부 조회)
    name = person['name'].replace(' ', '')
    
    # 폰번호, 부서 조건 없이 오직 이름으로만 검색
    query = """
        SELECT * FROM training_history 
        WHERE REPLACE(name, ' ', '') = ? 
        ORDER BY training_date DESC
    """
    c.execute(query, (name,))
    
    # 결과를 리스트로 변환
    history = [dict(r) for r in c.fetchall()]
    conn.close()
    
    return {'person': person, 'history': history}

# (2) 신규 등록 API (추가됨)
@app.route('/api/personnel/add', methods=['POST'])
@login_required
def add_personnel():
    try:
        set_id = request.form['set_id']
        dept = request.form['dept']
        name = request.form['name']
        position = request.form['position']
        phone = request.form['phone']
        email = request.form['email'] # [추가]
        role = request.form['emergency_role']
        desig_date = request.form['designation_date']
        target_type = '신규' 
        
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        # email 컬럼 추가
        c.execute("""
            INSERT INTO personnel (set_id, dept, name, position, phone, email, emergency_role, designation_date, target_type)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (set_id, dept, name, position, phone, email, role, desig_date, target_type))
        conn.commit()
        conn.close()
        return {'status': 'success', 'msg': '등록되었습니다.'}
    except Exception as e:
        return {'status': 'error', 'msg': str(e)}

@app.route('/api/personnel/update', methods=['POST'])
@login_required
def update_personnel():
    try:
        p_id = request.form['p_id']
        dept = request.form['dept']
        name = request.form['name']
        position = request.form['position']
        phone = request.form['phone']
        email = request.form['email'] # [추가]
        role = request.form['emergency_role']
        desig_date = request.form['designation_date']
        
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        # email 업데이트 추가
        c.execute("""
            UPDATE personnel 
            SET dept=?, name=?, position=?, phone=?, email=?, emergency_role=?, designation_date=?
            WHERE id=?
        """, (dept, name, position, phone, email, role, desig_date, p_id))
        conn.commit()
        conn.close()
        return {'status': 'success', 'msg': '수정되었습니다.'}
    except Exception as e:
        return {'status': 'error', 'msg': str(e)}

# (4) 삭제 API
@app.route('/api/personnel/delete', methods=['POST'])
@login_required
def delete_personnel():
    try:
        p_id = request.form['p_id']
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("DELETE FROM personnel WHERE id=?", (p_id,))
        conn.commit()
        conn.close()
        return {'status': 'success', 'msg': '삭제되었습니다.'}
    except Exception as e:
        return {'status': 'error', 'msg': str(e)}

# === 2. 엑셀 다운로드 라우트 ===
@app.route('/download_excel')
@login_required
def download_excel():
    set_id = request.args.get('set_id')
    try:
        target_year = int(request.args.get('target_year', datetime.now().year))
    except:
        target_year = datetime.now().year

    conn = sqlite3.connect(DB_PATH)
    
    # 1. 인사 정보 조회
    query = """
        SELECT p.*, d.sort_order
        FROM personnel p
        LEFT JOIN departments d 
          ON REPLACE(p.dept, ' ', '') = REPLACE(d.dept_name, ' ', '')
        WHERE p.set_id = ? 
        ORDER BY 
            COALESCE(d.sort_order, 9999) ASC,
            p.dept ASC,
            p.name ASC
    """
    df_p = pd.read_sql_query(query, conn, params=(set_id,))
    
    # 2. 교육 이력 조회
    df_h = pd.read_sql_query("SELECT * FROM training_history ORDER BY training_date DESC", conn)
    conn.close()

    # 데이터 전처리
    df_p['email'] = df_p['email'].fillna('').astype(str).str.strip()
    df_h['email'] = df_h['email'].fillna('').astype(str).str.strip()
    
    if 'training_year' not in df_h.columns:
        df_h['training_year'] = pd.to_numeric(df_h['training_date'].astype(str).str[:4], errors='coerce').fillna(0).astype(int)
    else:
        df_h['training_year'] = pd.to_numeric(df_h['training_year'], errors='coerce').fillna(0).astype(int)

    final_rows = []
    today = datetime.now().date()

    for i, row in df_p.iterrows():
        email = row['email']
        d_date = pd.to_datetime(row['designation_date'], errors='coerce')
        
        # === 1. 매칭 (이메일 엄격 모드) ===
        my_history = pd.DataFrame()
        if email and len(email) > 2 and email.lower() != 'nan':
            match = df_h[df_h['email'] == email]
            if not match.empty:
                my_history = match.copy()
        
        # === 2. 교육구분 판별 ===
        edu_type = "신규"
        if pd.notnull(d_date):
            if d_date.year == target_year:
                edu_type = "신규"
            elif d_date.year < target_year:
                if not my_history.empty:
                    edu_type = "보수"
                else:
                    edu_type = "신규"
        else:
            if not my_history.empty: edu_type = "보수"

        # === 3. 이수 여부 (표시 형식 개선) ===
        status = "미이수"
        complete_date = ""
        
        if not my_history.empty:
            # 날짜순 정렬 (최신순)
            my_history = my_history.sort_values(by='training_date', ascending=False)
            top = my_history.iloc[0] # 가장 최근 기록
            
            # 해당 연도(target_year) 이수 기록 확인
            this_year_hist = my_history[my_history['training_year'] == target_year]
            
            if not this_year_hist.empty:
                # [CASE 1] 올해 이수함 -> 이수(2026)
                rec = this_year_hist.iloc[0]
                status = f"이수({int(rec['training_year'])})"
                complete_date = rec['training_date']
            else:
                # [CASE 2] 올해는 안받았지만 과거 이력 있음 -> 이수(2024) 로 표시 요청
                status = f"이수({int(top['training_year'])})"
                complete_date = top['training_date']
        
        # [CASE 3] 아예 이력이 없는 경우 -> 6개월 이내인지 체크
        if status == "미이수" and pd.notnull(d_date):
            try:
                diff = (today - d_date.date()).days
                if 0 <= diff <= 180: status = "6개월이내"
            except: pass

        # === 4. 이수 횟수 및 전체 이력 ===
        history_str = ""
        training_count = 0
        if not my_history.empty:
            training_count = len(my_history)
            sorted_dates = my_history['training_date'].unique()
            history_str = ", ".join([str(d) for d in sorted_dates if pd.notnull(d) and str(d).strip() != ''])

        final_rows.append({
            '연번': i + 1,
            '기준년도': target_year,
            '부서': row['dept'],
            '직급': row['position'],
            '이름': row['name'],
            '연락처': row['phone'],
            '이메일': email,
            '비상시임무': row['emergency_role'],
            '지정일자': row['designation_date'],
            '교육구분': edu_type,
            '이수여부': status,       # [수정됨] 이수(20XX) or 미이수
            '최근교육일': complete_date,
            '총이수횟수': training_count,
            '전체교육이력(날짜)': history_str 
        })

    # 엑셀 생성
    df_export = pd.DataFrame(final_rows)
    
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
        df_export.to_excel(writer, index=False, sheet_name='방재요원현황')
        
        workbook = writer.book
        worksheet = writer.sheets['방재요원현황']
        
        # 자동 필터 적용
        (max_row, max_col) = df_export.shape
        worksheet.autofilter(0, 0, max_row, max_col - 1)
        
        # 컬럼 폭 자동 조절
        for idx, col in enumerate(df_export.columns):
            max_len = max(df_export[col].astype(str).map(len).max(), len(col)) + 2
            if max_len > 60: max_len = 60
            worksheet.set_column(idx, idx, max_len)

    output.seek(0)
    filename = f"방재요원 현황_{target_year}년기준_{datetime.now().strftime('%Y%m%d')}.xlsx"
    
    return send_file(
        output,
        as_attachment=True,
        download_name=filename,
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    )

# === 3. 파일 업로드 라우트 (휴대폰 번호 인식 강화) ===
# app.py 의 upload_action 함수 (완전체)

@app.route('/upload_action', methods=['POST'])
@login_required
def upload_action():
    type_ = request.form['type']
    file = request.files['file']
    
    if not file:
        flash("파일이 없습니다.")
        return redirect(url_for('personnel_list'))
    
    try:
        # === 1. 부서 정렬 순서 등록 ===
        if type_ == 'dept_order':
            xls = pd.ExcelFile(file)
            df = pd.read_excel(xls, header=None)
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute("DELETE FROM departments")
            count = 0
            for i, row in df.iterrows():
                dept_name = str(row[0]).strip()
                if dept_name:
                    c.execute("INSERT INTO departments (dept_name, sort_order) VALUES (?, ?)", (dept_name, i+1))
                    count += 1
            conn.commit(); conn.close()
            flash(f"✅ 부서 정렬 순서 {count}건 등록 완료!")

        # === 2. 인사발령 명단 등록 ===
        elif type_ == 'personnel':
            set_name = request.form['set_name']
            xls = pd.ExcelFile(file)
            target_df = None
            for sheet in xls.sheet_names:
                df = pd.read_excel(xls, sheet_name=sheet)
                df.columns = [str(c).replace("\n","").replace(" ","").strip() for c in df.columns]
                if '이름' in df.columns:
                    target_df = df; break
            
            if target_df is None: raise Exception("이름 컬럼을 찾을 수 없습니다.")

            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute("INSERT INTO personnel_sets (set_name, created_date) VALUES (?, ?)", 
                      (set_name, datetime.now().strftime("%Y-%m-%d")))
            set_id = c.lastrowid
            
            count = 0
            for _, row in target_df.iterrows():
                name = row.get('이름'); dept = row.get('소속3') or row.get('소속') or row.get('부서')
                phone = str(row.get('휴대전화', row.get('연락처', '')))
                emer_role = str(row.get('비상시직위', row.get('비상시임무', '')))
                if emer_role == 'nan': emer_role = ''
                
                # [추가] 이메일 읽기
                email = str(row.get('이메일', row.get('email', row.get('E-mail', ''))))
                if email == 'nan': email = ''
                
                desig_date = ''
                for col in target_df.columns:
                    if '지정일자' in col:
                        raw_d = row.get(col)
                        if pd.notna(raw_d):
                            try:
                                if isinstance(raw_d, datetime): desig_date = raw_d.strftime("%Y-%m-%d")
                                else: desig_date = str(raw_d).split(' ')[0]
                            except: pass
                        break
                
                if pd.isna(name) or not str(name).strip(): continue
                target_type = '신규'
                
                # INSERT 쿼리에 email 추가
                c.execute("""
                    INSERT INTO personnel 
                    (set_id, dept, name, position, emergency_role, phone, email, target_type, designation_date) 
                    VALUES (?,?,?,?,?,?,?,?,?)
                """, (set_id, str(dept), str(name), str(row.get('직급','')), emer_role, phone, email, target_type, desig_date))
                count += 1
                
            conn.commit(); conn.close()
            flash(f"✅ '{set_name}' 명단 {count}명 등록 완료!")

        # === 3. 교육 이수 명단 등록 (수정됨) ===
        elif type_ == 'training':
            xls = pd.ExcelFile(file)
            conn = sqlite3.connect(DB_PATH); c = conn.cursor()
            total_cnt = 0
            
            for sheet in xls.sheet_names:
                if "총괄" in sheet or "집계" in sheet: continue
                
                # 헤더 찾기
                temp = pd.read_excel(xls, sheet_name=sheet, nrows=20, header=None)
                header_idx = -1
                for idx, row in temp.iterrows():
                    r_str = " ".join([str(x) for x in row])
                    if ('성명' in r_str or '이름' in r_str) and ('부서' in r_str or '소속' in r_str):
                        header_idx = idx; break
                if header_idx == -1: continue
                
                df = pd.read_excel(xls, sheet_name=sheet, header=header_idx)
                df.columns = [str(col).replace("\n","").replace(" ","").strip() for col in df.columns]
                
                for _, row in df.iterrows():
                    name = row.get('성명') or row.get('이름')
                    if not name or str(name) == 'nan' or str(name) == '이름': continue
                    
                    dept = row.get('부서') or row.get('소속')
                    
                    # 휴대폰 번호 찾기
                    phone = ''
                    for p_col in ['연락처', '휴대전화', '휴대폰', '전화번호', '모바일', 'H.P']:
                        if p_col in df.columns:
                            val = row.get(p_col)
                            if pd.notna(val): phone = str(val).strip()
                            break
                    
                    # [추가] 이메일 읽기
                    email = ''
                    for e_col in ['이메일', 'email', 'E-mail', '전자우편']:
                        if e_col in df.columns:
                            val = row.get(e_col)
                            if pd.notna(val): email = str(val).strip()
                            break
                    
                    # 교육구분 및 시간
                    edu_type_raw = str(row.get('교육구분', ''))
                    hours = 18 if '신규' in edu_type_raw else 8
                    edu_type = '신규' if hours == 18 else '보수'
                    
                    # 교육일 날짜 처리 (2025.11.11. 같은 형식 대응)
                    raw_date = row.get('교육일')
                    t_date = datetime.now().strftime("%Y.%m.%d")
                    if pd.notna(raw_date):
                        try:
                            if isinstance(raw_date, datetime):
                                t_date = raw_date.strftime("%Y.%m.%d")
                            else:
                                t_date = str(raw_date).replace('-', '.').strip().rstrip('.') # 끝에 점 제거
                                t_date = t_date.split(' ')[0]
                        except: pass
                    
                    # 연도 추출
                    try: t_year = int(t_date.split('.')[0])
                    except: t_year = datetime.now().year

                    # 재난안전 여부
                    safety_val = ''
                    for col in df.columns:
                        if '재난' in col and ('대상' in col or '여부' in col):
                            if str(row.get(col,'')).strip() in ['○','O','0','대상']: safety_val = 'O'
                    
                    # 중복 체크 및 저장
                    chk = "SELECT id FROM training_history WHERE name=? AND dept=? AND training_date=?"
                    prm = [str(name), str(dept), t_date]
                    if phone: # 폰번호가 있을 때만 체크 조건에 추가
                        chk += " AND phone=?"
                        prm.append(str(phone))
                    
                    c.execute(chk, tuple(prm))
                    if not c.fetchone():
                        c.execute('''INSERT INTO training_history 
                                 (name, dept, phone, email, training_date, training_year, training_type, hours, safety_status) 
                                 VALUES (?,?,?,?,?,?,?,?,?)''',
                              (str(name), str(dept), phone, email, t_date, t_year, edu_type, hours, safety_val))
                        total_cnt += 1
            
            conn.commit(); conn.close()
            flash(f"✅ 교육 이수 내역 {total_cnt}건 등록 완료!")

    except Exception as e:
        flash(f"❌ 에러 발생: {str(e)}")
        
    return redirect(url_for('personnel_list'))
    
# === [신규] 매칭 관리자 페이지 ===
@app.route('/matching')
@login_required
def matching():
    conn = sqlite3.connect(DB_PATH)
    
    # 1. 현재 선택된 세트의 요원 명단 조회
    selected_set_id = request.args.get('set_id')
    sets = conn.execute("SELECT id, set_name FROM personnel_sets ORDER BY id DESC").fetchall()
    if sets and not selected_set_id: selected_set_id = sets[0][0]
    
    personnel = []
    if selected_set_id:
        # 이메일과 매칭 상태를 확인하기 위해 쿼리
        query = "SELECT * FROM personnel WHERE set_id = ? ORDER BY name"
        df = pd.read_sql_query(query, conn, params=(selected_set_id,))
        personnel = df.to_dict('records')

    # 2. 전체 교육 이력 조회 (검색용)
    history_query = "SELECT * FROM training_history ORDER BY training_date DESC"
    history = pd.read_sql_query(history_query, conn).to_dict('records')
    
    conn.close()
    return render_template('matching.html', sets=sets, current_set_id=int(selected_set_id or 0), personnel=personnel, history=history)

# === [신규] 매칭 확정 API ===
@app.route('/api/confirm_match', methods=['POST'])
@login_required
def confirm_match():
    try:
        p_id = request.form['p_id']
        email = request.form['email']
        # h_ids는 쉼표로 구분된 문자열로 받음 (예: "1,4,5")
        h_ids_str = request.form.get('h_ids', '')
        
        if not email or len(email) < 3:
            return {'status': 'error', 'msg': '연결할 이메일을 입력해주세요.'}

        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        
        # 1. 방재요원 명단에 이메일 업데이트
        c.execute("UPDATE personnel SET email = ? WHERE id = ?", (email, p_id))
        
        # 2. 선택된 교육 이력들에 이메일 일괄 업데이트
        if h_ids_str:
            # "1,3,5" -> (1, 3, 5) 튜플 변환
            h_ids = tuple(map(int, h_ids_str.split(',')))
            # SQLite의 IN 절을 사용하여 한 번에 업데이트
            query = f"UPDATE training_history SET email = ? WHERE id IN ({','.join(['?']*len(h_ids))})"
            c.execute(query, (email, *h_ids))
        
        conn.commit()
        conn.close()
        return {'status': 'success', 'msg': f'✅ 매칭 완료! 이메일 [{email}]로 연결되었습니다.'}
    except Exception as e:
        return {'status': 'error', 'msg': str(e)}


@app.route('/db_manager', methods=['GET', 'POST'])
@login_required
def db_manager():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    
    c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name != 'sqlite_sequence' ORDER BY name")
    tables = [row['name'] for row in c.fetchall()]
    
    # [🚨 여기가 범인입니다!]
    # 기존 코드: query_result = None  <-- 이걸 지우고
    # 아래 코드로 바꿔주세요.
    query_result = []  # <-- 이렇게 빈 리스트로 초기화해야 에러가 안 납니다.
    
    columns = []
    error_msg = None
    sql_query = request.form.get('sql_query', '')
    
    # 2. 쿼리 실행 요청이 있을 때
    if request.method == 'POST' and sql_query.strip():
        try:
            # 트랜잭션 시작
            if any(k in sql_query.upper() for k in ['UPDATE', 'INSERT', 'DELETE', 'DROP', 'ALTER']):
                c.executescript(sql_query) # 여러 줄 실행 가능
                conn.commit()
                flash("✅ 쿼리가 성공적으로 실행되었습니다.")
            else:
                # SELECT 문인 경우
                c.execute(sql_query)
                data = c.fetchall()
                if data:
                    columns = data[0].keys() # 컬럼명 추출
                    query_result = data
                else:
                    columns = [desc[0] for desc in c.description] # 데이터 없어도 컬럼명은 표시
        except Exception as e:
            error_msg = f"SQL 오류: {str(e)}"
    
    conn.close()
    
    return render_template('db_manager.html', 
                           tables=tables, 
                           sql_query=sql_query, 
                           columns=columns, 
                           query_result=query_result, 
                           error_msg=error_msg)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=1111)
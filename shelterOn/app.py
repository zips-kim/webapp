import os
import shutil
from datetime import datetime
from functools import wraps
import logging
from logging.handlers import RotatingFileHandler
import json
from io import BytesIO

# [New] 필요한 라이브러리 임포트
from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory, send_file, session
from flask_socketio import SocketIO, emit
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
from sqlalchemy import func, text, desc, and_
import pandas as pd
import requests
from sqlalchemy import inspect, select, func

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from functools import lru_cache

# [New] 모델 및 DB 객체 임포트 (models.py)
from models import db, User, Shelter, Resident, ResidentLog, Supply, DistributionLog, SupplyMovementLog, DutyOrder, StaffLog, AssemblyPoint, AssemblyDestination, Incident, TemplateShelter, TemplateAssembly, TemplateRoute

# ==========================================
# [1] 환경 설정 및 초기화
# ==========================================
load_dotenv() # .env 파일 로드

app = Flask(__name__)

# Config 설정
app.secret_key = os.getenv('SECRET_KEY', 'default_dev_key')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///shelter.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# 카카오 설정
KAKAO_REST_API_KEY = os.getenv('KAKAO_REST_API_KEY')
KAKAO_JS_KEY = os.getenv('KAKAO_JS_KEY')
KAKAO_REDIRECT_URI = 'http://localhost:7870/oauth/kakao/callback'

# DB 초기화
db.init_app(app)

# SocketIO 설정
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# 로깅 설정
log_filename = 'shelter_on.log'
formatter = logging.Formatter('[%(asctime)s] %(levelname)s in %(module)s: %(message)s')
file_handler = RotatingFileHandler(log_filename, maxBytes=5*1024*1024, backupCount=5, encoding='utf-8')
file_handler.setFormatter(formatter)
file_handler.setLevel(logging.INFO)
app.logger.addHandler(file_handler)
app.logger.setLevel(logging.INFO)

# ==========================================
# [2] 공통 유틸리티 및 보안 설정
# ==========================================
# 헬퍼 함수: 실시간 알림 전송 공통화
def send_sys_notification(message, incident_id=None, shelter_id=None, resident_id=None, supply_id=None):
    # 1. 로그 확인용
    print(f"🚀 [전송시도] 메시지: {message}") 
    
    try:
        # broadcast=True 옵션 삭제 (자동으로 전체 전송됨)
        socketio.emit('sys_notification', {
            'message': message,
            'incident_id':incident_id,
            'shelter_id': shelter_id,
            'resident_id': resident_id,
            'supply_id': supply_id,
            'time': datetime.now().strftime('%H:%M:%S')
        }, namespace='/') 
        
        flash(message)
                
    except Exception as e:
        print(f"❌ [전송실패] 에러 발생: {e}")
    
def broadcast_update():
    """데이터가 변경되었음을 모든 클라이언트에게 알림"""
    socketio.emit('map_update', {'msg': 'refresh_required'})
    
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            if request.endpoint not in ['login', 'login_resident', 'user_register', 'add_resident', 'kakao_resident_login', 'kakao_callback']:
                return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


@app.template_filter('format_number')
def format_number(value):
    try:
        return "{:,}".format(int(value))
    except (ValueError, TypeError):
        return value

# ==========================================
# [3] 라우트: 인증 및 메인
# ==========================================
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        login_id = request.form.get('login_id')
        password = request.form.get('password')
        user = User.query.filter_by(login_id=login_id).first()

        if user and check_password_hash(user.password, password):
            session['logged_in'] = True
            session['role'] = user.role_level
            session['role_level'] = user.role_level
            session['user_name'] = "관리자" if user.role_level < 3 else user.login_id
            
            # [변경] 로그인 후 바로 지도가 아닌 '사고 선택' 화면으로
            return redirect(url_for('incident'))
        else:
            flash("아이디 또는 비밀번호가 틀렸습니다.")
    return render_template('login.html')
        
@app.route('/login1', methods=['GET', 'POST'])
def login1():
    if request.method == 'POST':
        login_id = request.form.get('login_id')
        password = request.form.get('password')
        role_type = request.form.get('role_type')

        user = User.query.filter_by(login_id=login_id).first()

        if user and check_password_hash(user.password, password):
            session['logged_in'] = True
            session['role'] = user.role_level
            
            app.logger.info(f"🔑 로그인 성공: {login_id} ({role_type})")

            # [수정] 근무자(Staff)인 경우
            if role_type == 'staff':
                # 여기서 바로 로그를 남기지 않습니다 (아직 누군지 모름)
                # 대신 임시 세션을 설정하고 '본인 선택 페이지'로 보냅니다.
                session['temp_staff_login'] = True 
                
                # (선택) 만약 로그인 화면에서 구호소를 선택했다면 미리 세션에 저장
                shelter_id = request.form.get('shelter_id')
                if shelter_id:
                    session['pre_selected_shelter_id'] = shelter_id
                    
                return redirect('/staff_select')
            
            # 관리자인 경우
            else:
                session['user_name'] = "관리자"
                return redirect('/')
        else:
            flash("아이디 또는 비밀번호가 틀렸습니다.")
            return redirect(url_for('login'))
    else:
        shelters = Shelter.query.filter_by(is_active=True).all()
        return render_template('login.html', shelters=shelters)


@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')


# ==========================================
# [3] 사고관리
# ==========================================
# [신규] 사고 관리 및 선택 API
# [신규] 사고 관리 및 선택 페이지
INCIDENT_TYPES = ['일반', '화재', '산불', '산사태', '풍수해', '방사능', '지진']

@app.route('/')
@login_required
def incident():
    page = request.args.get('page', 1, type=int)
    status_filter = request.args.get('status', 'ACTIVE')
    search = request.args.get('search', '')

    query = Incident.query
    if status_filter:
        query = query.filter(Incident.status == status_filter)
    if search:
        query = query.filter(Incident.title.like(f'%{search}%'))

    per_page = 8
    pagination = query.order_by(Incident.incident_time.desc(), Incident.created_at.desc())\
                      .paginate(page=page, per_page=per_page, error_out=False)

    # [New] 각 사고별 통계 데이터 계산
    incidents_with_stats = []
    for inc in pagination.items:
        # 1. 시설 수
        s_count = Shelter.query.filter_by(incident_id=inc.id).count()
        a_count = AssemblyPoint.query.filter_by(incident_id=inc.id).count()
        
        # 2. 이재민 수 (등록된 총 인원)
        r_count = Resident.query.filter_by(incident_id=inc.id).count()

        # 3. 물품 총합 (잔여 재고 + 지급된 수량)
        # 3-1. 구호소 잔여 재고 (해당 사고에 속한 구호소들의 물품 합)
        remaining = db.session.query(func.sum(Supply.quantity))\
            .join(Shelter).filter(Shelter.incident_id == inc.id).scalar() or 0
        
        # 3-2. 지급된 수량
        distributed = db.session.query(func.sum(DistributionLog.quantity))\
            .filter(DistributionLog.incident_id == inc.id).scalar() or 0
            
        total_supplies = remaining + distributed
        
        # 객체에 임시 속성으로 할당
        inc.stat_shelters = s_count
        inc.stat_assemblies = a_count
        inc.stat_residents = r_count
        inc.stat_supplies = total_supplies
        
        incidents_with_stats.append(inc)

    count_active = Incident.query.filter_by(status='ACTIVE').count()
    count_closed = Incident.query.filter_by(status='CLOSED').count()

    return render_template('incident.html', 
                           incidents=incidents_with_stats, # 통계 포함된 리스트 전달
                           pagination=pagination,
                           current_status=status_filter,
                           search=search,
                           cnt_active=count_active,
                           cnt_closed=count_closed,
                           incident_types=INCIDENT_TYPES)

# [New] 사고 상태 변경 (종료/재개) API 추가
@app.route('/incident/<int:incident_id>/toggle_status')
@login_required
def toggle_incident_status(incident_id):
    if session.get('role') > 2: return "권한이 없습니다.", 403
    
    inc = db.session.get(Incident, incident_id)
    if inc:
        # 상태 토글
        inc.status = 'CLOSED' if inc.status == 'ACTIVE' else 'ACTIVE'
        db.session.commit()
        flash(f"상태가 변경되었습니다. ({inc.status})")
    
    return redirect(url_for('incident'))

# [신규] 선택한 사고를 세션에 저장
@app.route('/set_incident/<int:incident_id>')
@login_required
def set_incident(incident_id):
    inc = db.session.get(Incident, incident_id)
    if inc:
        session['incident_id'] = inc.id
        session['incident_title'] = inc.title
        app.logger.info(f"🚩 사고 선택됨: {inc.title}")
        return redirect(url_for('index')) # 메인(대시보드)으로 이동
    return redirect(url_for('incident'))

# [신규] 사고 생성/삭제 (Level 1, 2 전용)
@app.route('/manage_incident', methods=['POST'])
@login_required
def manage_incident():
    if session.get('role') > 2:
        return "권한이 없습니다.", 403
    
    action = request.form.get('action')
    try:
        if action == 'create':
            inc_type = request.form.get('incident_type')
            new_inc = Incident(
                title=request.form.get('title'),
                incident_type=inc_type,
                incident_category=request.form.get('incident_category'),
                incident_time=request.form.get('incident_time'),
                description=request.form.get('description')
            )
            db.session.add(new_inc)
            db.session.flush() # ID 생성을 위해 flush

            # --- 템플릿 데이터 복사 시작 ---
            # 1. 구호소 복사
            t_shelters = TemplateShelter.query.filter_by(incident_type=inc_type).all()
            s_map = {} # {TemplateID: NewID}
            for ts in t_shelters:
                ns = Shelter(incident_id=new_inc.id, name=ts.name, address=ts.address, 
                             phone=ts.phone, area=ts.area, capacity=ts.capacity, 
                             latitude=ts.latitude, longitude=ts.longitude, is_active=True)
                db.session.add(ns)
                db.session.flush()
                s_map[ts.id] = ns.id

            # 2. 집결지 복사
            t_assemblies = TemplateAssembly.query.filter_by(incident_type=inc_type).all()
            a_map = {}
            for ta in t_assemblies:
                na = AssemblyPoint(incident_id=new_inc.id, name=ta.name, address=ta.address, 
                                   stop_no=ta.stop_no, latitude=ta.latitude, longitude=ta.longitude, is_active=True)
                db.session.add(na)
                db.session.flush()
                a_map[ta.id] = na.id

            # 3. 대피경로 복사
            t_routes = TemplateRoute.query.filter_by(incident_type=inc_type).all()
            for tr in t_routes:
                if tr.assembly_tmp_id in a_map and tr.shelter_tmp_id in s_map:
                    nr = AssemblyDestination(assembly_id=a_map[tr.assembly_tmp_id], 
                                             shelter_id=s_map[tr.shelter_tmp_id], 
                                             waypoints=tr.waypoints)
                    db.session.add(nr)
            # --- 템플릿 데이터 복사 종료 ---
        elif action == 'delete':
            inc_id = request.form.get('incident_id')
            inc = db.session.get(Incident, inc_id)
            if inc: db.session.delete(inc)
            
        db.session.commit()
        return redirect(url_for('incident'))
    except Exception as e:
        db.session.rollback()
        return str(e), 500
        
@app.route('/admin/template')
@login_required
def admin_template():
    if session.get('role') > 2: return "권한 없음", 403
    selected_type = request.args.get('type', '화재')
    t_shelters = TemplateShelter.query.filter_by(incident_type=selected_type).all()
    t_assemblies = TemplateAssembly.query.filter_by(incident_type=selected_type).all()
    return render_template('admin_template.html', types=INCIDENT_TYPES, 
                           selected_type=selected_type, shelters=t_shelters, assemblies=t_assemblies)


@app.route('/init_templete')
#@login_required
def init_radiological_template():
    #if session.get('role') > 2: return "권한 없음", 403

    try:
        # [C] 계정 생성
        User.query.delete()
        # Role Level -> 1:최고관리자(zips), 2:모니터/일반관리자, 3:현장근무자
        users = [
            User(login_id='zips', password=generate_password_hash('zips7870!'), role_level=1),
            User(login_id='admin', password=generate_password_hash('dnjswkfur'), role_level=2),
            User(login_id='monitor', password=generate_password_hash('dnjswkfur'), role_level=2),
            User(login_id='staff', password=generate_password_hash('dnjswkfur'), role_level=3)
        ]
        db.session.add_all(users)
        
        # [D] 샘플 물품 데이터
        Supply.query.delete()
        supplies = [
            Supply(id=1, item_name='구호세트(남/대)', quantity=12, shelter_id=None),
            Supply(id=2, item_name='구호세트(남/중)', quantity=22, shelter_id=None),
            Supply(id=3, item_name='구호세트(남/소)', quantity=8, shelter_id=None),
            Supply(id=4, item_name='구호세트(여/대)', quantity=12, shelter_id=None),
            Supply(id=5, item_name='구호세트(여/중)', quantity=23, shelter_id=None),
            Supply(id=6, item_name='구호세트(여/소)', quantity=8, shelter_id=None),
            Supply(id=7, item_name='취사세트', quantity=34, shelter_id=None)
        ]
        db.session.add_all(supplies)
            
        # 1. 기존 '방사능' 템플릿 삭제 (중복 방지)
        TemplateShelter.query.filter_by(incident_type='방사능').delete()
        TemplateAssembly.query.filter_by(incident_type='방사능').delete()

        # 2. 제공된 구호소 데이터 -> TemplateShelter로 변환 삽입
        shelter_templates = [
            TemplateShelter(incident_type='방사능', name='유성종합스포츠센터', address='대전광역시 유성구 유성대로 978', phone='', area=4986, capacity=1385, latitude=36.379005, longitude=127.343324),
            TemplateShelter(incident_type='방사능', name='지족초등학교', address='대전광역시 유성구 노은서로 238', phone='042-824-3144', area=12100, capacity=3661, latitude=36.380684, longitude=127.317369),
            TemplateShelter(incident_type='방사능', name='지족중학교', address='대전광역시 유성구 노은동로 193', phone='042-477-4640', area=13791, capacity=4172, latitude=36.378244, longitude=127.320588),
            TemplateShelter(incident_type='방사능', name='지족고등학교', address='대전광역시 유성구 노은서로 202', phone='042-476-2706', area=12778, capacity=3866, latitude=36.378134, longitude=127.315549),
            TemplateShelter(incident_type='방사능', name='노은초등학교', address='대전광역시 유성구 노은동로99번길 35', phone='042-476-1492', area=13120, capacity=3969, latitude=36.368924, longitude=127.321425),
            TemplateShelter(incident_type='방사능', name='노은중학교', address='대전광역시 유성구 노은동로 104', phone='042-479-5554', area=13033, capacity=3943, latitude=36.370082, longitude=127.324187),
            TemplateShelter(incident_type='방사능', name='노은고등학교', address='대전광역시 유성구 노은동로99번길 55', phone='042-717-3600', area=11438, capacity=3460, latitude=36.369013, longitude=127.319228),
            TemplateShelter(incident_type='방사능', name='유성중학교', address='대전광역시 유성구 상대로 33', phone='042-822-1605', area=13833, capacity=4185, latitude=36.345903, longitude=127.334768),
            TemplateShelter(incident_type='방사능', name='봉명초등학교', address='대전광역시 유성구 계룡로132번길 62', phone='042-820-8800', area=13549, capacity=4099, latitude=36.349582, longitude=127.343527),
            TemplateShelter(incident_type='방사능', name='봉명중학교', address='대전광역시 유성구 계룡로132번길 71', phone='042-826-6872', area=12764, capacity=3862, latitude=36.349713, longitude=127.344561),
            TemplateShelter(incident_type='방사능', name='상대초등학교', address='대전광역시 유성구 월드컵대로 321', phone='042-826-1720', area=10202, capacity=3087, latitude=36.347635, longitude=127.336504),
            TemplateShelter(incident_type='방사능', name='원신흥초등학교', address='대전광역시 유성구 원신흥로55번길 37', phone='042-826-9811', area=9231, capacity=2793, latitude=36.340858, longitude=127.342506),
            TemplateShelter(incident_type='방사능', name='흥도초등학교', address='대전광역시 유성구 도안동로 323', phone='042-822-5083', area=11069, capacity=3349, latitude=36.334103, longitude=127.338713)
        ]

        # 3. 제공된 집결지 데이터 -> TemplateAssembly로 변환 삽입
        assembly_templates = [
            TemplateAssembly(incident_type='방사능', name='관평동주민센터', stop_no='', address='대전광역시 유성구 관평2로 42', latitude=36.423096, longitude=127.388922),
            TemplateAssembly(incident_type='방사능', name='구즉동주민센터', stop_no='82520', address='대전광역시 유성구 구룡달전로 22', latitude=36.440336, longitude=127.383784),
            TemplateAssembly(incident_type='방사능', name='한국원자력연구원', stop_no='', address='대전광역시 유성구 덕진동 453', latitude=36.420748, longitude=127.375128),
            TemplateAssembly(incident_type='방사능', name='관평중학교', stop_no='', address='대전광역시 유성구 관평동 901', latitude=36.424873, longitude=127.388094),
            TemplateAssembly(incident_type='방사능', name='관평초등학교', stop_no='', address='대전광역시 유성구 관평동 900', latitude=36.423731, longitude=127.387190),
            TemplateAssembly(incident_type='방사능', name='배울초등학교', stop_no='', address='대전광역시 유성구 배울2로 8', latitude=36.422048, longitude=127.384434),
            TemplateAssembly(incident_type='방사능', name='롯데마트대덕점', stop_no='44590', address='대전광역시 유성구 테크노중앙로 36', latitude=36.426896, longitude=127.389686),
            TemplateAssembly(incident_type='방사능', name='수변공원', stop_no='44670', address='대전광역시 유성구 테크노중앙로 68', latitude=36.425588, longitude=127.392873),
            TemplateAssembly(incident_type='방사능', name='테크노밸리6단지', stop_no='47100', address='대전광역시 유성구 관평동 683', latitude=36.418499, longitude=127.387979),
            TemplateAssembly(incident_type='방사능', name='두리초등학교', stop_no='', address='대전광역시 유성구 와룡로 37', latitude=36.429395, longitude=127.382383),
            TemplateAssembly(incident_type='방사능', name='두리중학교', stop_no='', address='대전광역시 유성구 와룡로37번길 20', latitude=36.429054, longitude=127.381100),
            TemplateAssembly(incident_type='방사능', name='한솔아파트', stop_no='44750', address='대전광역시 유성구 구즉로 25', latitude=36.432691, longitude=127.384381),
            TemplateAssembly(incident_type='방사능', name='북부여성가족원', stop_no='44840', address='대전광역시 유성구 대덕대로 1173', latitude=36.431323, longitude=127.387177),
            TemplateAssembly(incident_type='방사능', name='송강전통시장입구', stop_no='44830', address='대전광역시 유성구 봉산로 17', latitude=36.435290, longitude=127.387256),
            TemplateAssembly(incident_type='방사능', name='휴먼시아아파트', stop_no='44770', address='대전광역시 유성구 와룡로136번길 75', latitude=36.437984, longitude=127.385128),
            TemplateAssembly(incident_type='방사능', name='송강중학교', stop_no='', address='대전광역시 유성구 와룡로 122', latitude=36.437677, longitude=127.381738),
            TemplateAssembly(incident_type='방사능', name='송강초등학교', stop_no='', address='대전광역시 유성구 송강로42번길 6', latitude=36.434487, longitude=127.384016)
        ]

        db.session.add_all(shelter_templates)
        db.session.add_all(assembly_templates)
        db.session.commit()
        
        flash("✅ 방사능 사고 대응 템플릿이 성공적으로 생성되었습니다.")
        return redirect(url_for('admin_template', type='방사능'))

    except Exception as e:
        db.session.rollback()
        return f"❌ 오류 발생: {str(e)}", 500
        
# ==========================================
# [3] 근무자(명령) 관리 (Admin)
# ==========================================

@app.route('/finish_work')
@login_required
def finish_work():
    user_name = session.get('user_name')
    shelter_id = session.get('shelter_id')
    
    if user_name and shelter_id:
        try:
            # 가장 최근의 퇴근하지 않은 로그 찾기
            last_log = StaffLog.query.filter_by(
                user_name=user_name, shelter_id=shelter_id, logout_time=None
            ).order_by(StaffLog.login_time.desc()).first()
            
            if last_log:
                last_log.logout_time = datetime.now()
                db.session.commit()
                
                msg = f"[{session['dept']} {session['user_name']}] 근무 종료"
                #send_sys_notification(msg, shelter_id)
                app.logger.info(f"🏁 근무 종료: {user_name}")
                
        except Exception as e:
            app.logger.error(f"근무 종료 오류: {e}")
            
    session.clear()
    return redirect(url_for('login'))


@app.route('/login_resident', methods=['POST'])
def login_resident():
    """주민이 자신의 입소 정보를 조회하기 위한 로그인 (ORM 적용)"""
    try:
        name = request.form.get('name')
        phone = request.form.get('phone')
        
        # 이름과 전화번호가 일치하는 주민 검색
        # (Resident 모델 사용)
        resident = Resident.query.filter_by(name=name, phone=phone).first()
        
        if resident:
            # 입소 이력이 있는지 확인하려면 logs 관계를 체크할 수도 있습니다.
            return redirect(url_for('user_info', resident_id=resident.id))
        
        return "<script>alert('일치하는 입소 정보가 없습니다.'); history.back();</script>"
        
    except Exception as e:
        app.logger.error(f"❌ 주민로그인 실패 ({name}): {str(e)}")
        return "<script>alert('오류가 발생했습니다.'); history.back();</script>"


@app.route('/staff_select')
def staff_select():
    """근무자 공용 로그인 후, 본인 선택 페이지 (ORM 적용)"""
    # 이 페이지는 /login에서 'temp_staff_login' 세션을 설정한 후 접근한다고 가정
    if not session.get('temp_staff_login'):
        return redirect('/login')
        
    # 근무 중이 아닌(is_working=False) 명령서만 가져옴 + 구호소 정보 조인
    # (DutyOrder.shelter 관계 활용)
    orders = DutyOrder.query.join(Shelter).filter(DutyOrder.is_working == False).order_by(Shelter.name, DutyOrder.dept).all()
    
    # 구호소별로 그룹화
    orders_by_shelter = {}
    for order in orders:
        sh_name = order.shelter.name
        if sh_name not in orders_by_shelter:
            orders_by_shelter[sh_name] = []
            
        orders_by_shelter[sh_name].append({
            'id': order.id, 
            'name': order.name, 
            'dept': order.dept, 
            'mission': order.mission
        })
        
    return render_template('staff_select.html', orders_by_shelter=orders_by_shelter)


@app.route('/start_work', methods=['POST'])
def start_work():
    """선택한 근무 명령으로 실제 근무 세션 시작 (ORM 적용)"""
    if not session.get('temp_staff_login'): 
        return redirect('/login')
    
    duty_id = request.form.get('duty_id')
    
    try:
        # 근무 명령 조회
        #order = DutyOrder.query.get(duty_id)
        order = db.session.get(DutyOrder, duty_id)
        
        if order:
            # 1. 세션 정보 확정
            session['logged_in'] = True
            session['role'] = 3
            session['user_name'] = order.name
            session['dept'] = order.dept
            session['mission'] = order.mission
            session['shelter_id'] = order.shelter_id
            session['shelter_name'] = order.shelter.name
            session['duty_id'] = duty_id 
            session.pop('temp_staff_login', None) # 임시 플래그 제거
            
            # 2. 근무 상태 변경 (DB Update)
            order.is_working = True
            
            # 3. 근무 로그 생성 (DB Insert)
            log = StaffLog(
                user_name=order.name,
                user_phone=order.phone,
                dept=order.dept,
                mission=order.mission,
                shelter_id=order.shelter_id,
                login_time=datetime.now()
            )
            db.session.add(log)
            
            # 변경 사항 커밋
            db.session.commit()
            
            # 4. 실시간 알림 전송
            msg = f"[{order.dept} {order.name}] {order.shelter.name} 근무를 시작합니다."
            #send_sys_notification(msg, order.shelter_id)
            
            return redirect('/')
        else:
            return "유효하지 않은 근무 명령입니다.", 400
            
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"❌ 근무 시작 처리 오류: {str(e)}")
        return "시스템 오류가 발생했습니다.", 500
    

@app.route('/admin/staff')
@login_required
def admin_staff():
    """근무 명령서 관리 페이지 (ORM 적용)"""
    if session.get('role') == 3: 
        return "권한이 없습니다.", 403
    
    # 1. 근무 명령 목록 조회 (근무 중인 사람을 상단으로, 그 외엔 구호소명 -> 이름 순 정렬)
    # Join을 사용하여 Shelter 정보까지 한 번에 로드하거나, relationship을 활용합니다.
    orders = db.session.query(DutyOrder).join(Shelter).order_by(
        DutyOrder.is_working.desc(), 
        Shelter.name, 
        DutyOrder.name
    ).all()
    
    # 템플릿 호환성을 위해 리스트 딕셔너리로 변환
    staff_list = []
    for o in orders:
        staff_list.append({
            'id': o.id,
            'name': o.name,
            'phone': o.phone,
            'dept': o.dept,
            'mission': o.mission,
            'is_working': o.is_working,
            'shelter_name': o.shelter.name  # relationship(backref) 활용
        })
    
    # 2. 구호소 목록 조회 (등록 폼용)
    all_shelters = Shelter.query.filter_by(is_active=True).all()
    # 템플릿의 select box 호환용 튜플 리스트
    shelter_options = [(s.id, s.name) for s in all_shelters]
    
    return render_template('admin_staff.html', staff_list=staff_list, all_shelters=shelter_options)


@app.route('/add_duty_order', methods=['POST'])
@login_required
def add_duty_order():
    if session.get('role') == 3: 
        return "권한이 없습니다.", 403

    try:
        new_order = DutyOrder(
            name=request.form['name'],
            dept=request.form['dept'],
            phone=request.form['phone'],
            mission=request.form['mission'],
            shelter_id=request.form['shelter_id'],
            is_working=False # 기본값
        )
        
        db.session.add(new_order)
        db.session.commit()
        
        broadcast_update()
        
        flash("✅ 근무 명령이 등록되었습니다.")
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error adding duty order: {e}")
        flash("❌ 등록 중 오류가 발생했습니다.")
        
    return redirect('/admin/staff')


@app.route('/delete_duty_order/<int:oid>')
@login_required
def delete_duty_order(oid):
    if session.get('role') == 3: 
        return "권한이 없습니다.", 403

    try:
        # [수정] DutyOrder.query.get_or_404(oid) -> db.session.get 사용
        order = db.session.get(DutyOrder, oid)
        if order:
            db.session.delete(order)
            db.session.commit()
            
            broadcast_update()
            flash("🗑️ 근무 명령이 삭제되었습니다.")
        else:
            flash("❌ 존재하지 않는 명령입니다.")
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error deleting duty order: {e}")
        flash("❌ 삭제 중 오류가 발생했습니다.")
        
    return redirect('/admin/staff')

# ==========================================
# [3] 메인 대시보드
# ==========================================
@app.route('/<int:incident_id>/index')
@login_required
def index(incident_id):
    try:
        inc = db.session.get(Incident, incident_id)
        if not inc:
            return redirect(url_for('incident'))
            
        # 1. 통계 (ORM 최적화)
        active_shelters = Shelter.query.filter_by(incident_id=incident_id, is_active=True).count()
        active_points = AssemblyPoint.query.filter_by(incident_id=incident_id, is_active=True).count()
        total_supplies = db.session.query(func.sum(Supply.quantity))\
            .join(Shelter).filter(Shelter.incident_id == incident_id).scalar() or 0
        
        # [수정] 현재 입소자 수 계산 로직 수정
        # 기존: .scalar_subquery()는 단일 값만 처리하여, 다수의 주민 상태를 놓치는 버그 발생
        # 변경: .in_(subquery)를 사용하여 각 주민별 최신 로그 ID 리스트 전체와 비교
        
        # 각 주민별 가장 최근(Max ID) 로그를 찾는 서브쿼리 정의
        max_id_subquery = db.session.query(func.max(ResidentLog.id))\
            .filter(ResidentLog.status != 'NOTE')\
            .group_by(ResidentLog.resident_id)

        # 전체 입소자 수
        current_residents = ResidentLog.query.filter(
            ResidentLog.id.in_(max_id_subquery),
            ResidentLog.status == 'IN'
        ).join(Shelter).filter(Shelter.incident_id == incident_id).count()

        stats = (None, current_residents, total_supplies, active_shelters, active_points)

        # 2. 구호소별 현황
        shelters_data = []
        shelters = Shelter.query.filter_by(incident_id=incident_id, is_active=True).all()
        for s in shelters:
            cnt = ResidentLog.query.filter(
                ResidentLog.id.in_(max_id_subquery),
                ResidentLog.shelter_id == s.id,
                ResidentLog.status == 'IN'
            ).count()
            shelters_data.append((s.id, s.name, s.capacity or 0, cnt))

        return render_template('index.html', stats=stats, shelters=shelters_data)
    except Exception as e:
        return redirect('/incident')

# 한 번 조회한 경로(출발+도착+경유지)는 서버 메모리에 저장해두고 재사용합니다.
@lru_cache(maxsize=1000)
def fetch_route_path(start_str, end_str, waypoints_str):
    rest_api_key = os.getenv('KAKAO_REST_API_KEY')
    if not rest_api_key: return []

    url = "https://apis-navi.kakaomobility.com/v1/directions"
    params = {
        "origin": start_str,
        "destination": end_str,
        "priority": "RECOMMEND",
    }
    if waypoints_str:
        params["waypoints"] = waypoints_str

    headers = {
        "Authorization": f"KakaoAK {rest_api_key}",
        "Content-Type": "application/json"
    }

    try:
        # verify=False는 SSL 에러 방지용
        resp = requests.get(url, params=params, headers=headers, verify=False)
        data = resp.json()

        
        path_points = []
        if 'routes' in data and len(data['routes']) > 0:
            for section in data['routes'][0]['sections']:
                for road in section['roads']:
                    vertexes = road['vertexes']
                    for i in range(0, len(vertexes), 2):
                        path_points.append({'lat': vertexes[i+1], 'lng': vertexes[i]})
        return path_points
    except Exception as e:
        # app.logger.error가 동작하지 않는 스코프일 수 있으므로 print로 대체하거나 app.logger 사용
        print(f"Server Route Fetch Error: {e}")
        return []


# 2. 프론트엔드(AJAX) 요청용 라우트
@app.route('/get_kakao_route')
def get_kakao_route():
    """
    [1:1 경로 탐색 API]
    요청: /get_kakao_route?start=X,Y&end=X,Y&way=X,Y|X,Y...
    """
    start = request.args.get('start') 
    end = request.args.get('end')
    way = request.args.get('way') 
    
    # 위에서 만든 캐싱 함수를 호출하여 결과를 재사용합니다.
    path_data = fetch_route_path(start, end, way)
    
    if path_data:
        return {'result': 'ok', 'path': path_data}
    else:
        return {'result': 'fail', 'msg': '경로를 찾을 수 없거나 API 오류'}

@app.route('/<int:incident_id>/map')
@login_required
def view_map(incident_id):
    inc = db.session.get(Incident, incident_id)
    if not inc:
        return redirect(url_for('incident'))
    
    current_role = session.get('role', 3)
    locations = []

    # [통계 집계용 변수]
    total_residents = 0
    total_active_shelters = 0
    
    # 1. [구호소] 조회
    # 활성 구호소만
    shelters = Shelter.query.filter_by(incident_id=incident_id).all()
    
    # 이재민 통계용 서브쿼리
    subq = select(func.max(ResidentLog.id))\
        .where(ResidentLog.status != 'NOTE')\
        .group_by(ResidentLog.resident_id)
    
    for s in shelters:
        # 개별 구호소 입소자 수
        res_count = ResidentLog.query.filter(
            ResidentLog.id.in_(subq),
            ResidentLog.shelter_id == s.id,
            ResidentLog.status == 'IN'
        ).count()

        staff_count = DutyOrder.query.filter_by(incident_id=incident_id, shelter_id=s.id).count()

        # [집계] 전체 통계 누적
        total_residents += res_count
        if s.is_active:
            total_active_shelters += 1

        locations.append({
            'id': s.id, 'name': s.name, 'lat': s.latitude, 'lng': s.longitude, 'type': 'shelter',
            'is_active': s.is_active, 'stat_resident': res_count, 'stat_staff': staff_count
        })

    # 2. [집결지] 조회
    assemblies = AssemblyPoint.query.filter_by(incident_id=incident_id).all()
    total_active_assemblies = 0 # [집계]

    for a in assemblies:
        if a.is_active:
            total_active_assemblies += 1
            
        if not a.latitude or not a.longitude: continue
        
        # ============================================================
        # [복구] 대피 경로 데이터 계산 로직 (이 부분이 누락되었었습니다)
        # ============================================================
        route_infos = []
        for link in a.destinations:
            # 연결된 구호소가 존재하면 경로 가져오기
            if link.target_shelter:
                sh = link.target_shelter
                if not sh.latitude or not sh.longitude: continue
                
                # 캐싱된 경로 탐색 함수 호출
                path_data = fetch_route_path(
                    f"{a.longitude},{a.latitude}", 
                    f"{sh.longitude},{sh.latitude}", 
                    link.waypoints or ""
                )

                route_infos.append({
                    'shelter_name': sh.name,
                    'path_data': path_data,
                    'target_active': sh.is_active
                })
        # ============================================================

        locations.append({
            'id': a.id, 'name': a.name, 'lat': a.latitude, 'lng': a.longitude, 'type': 'assembly',
            'is_active': a.is_active, 'route_infos': route_infos  # 복구된 경로 정보 포함
        })

    # 3. [물품] 전체 재고량 조회
    try:
        #total_supplies = db.session.query(func.sum(Supply.quantity)).scalar() or 0
        total_supplies = db.session.query(func.sum(Supply.quantity))\
        .join(Shelter).filter(Shelter.incident_id == incident_id).scalar() or 0
    except:
        total_supplies = 0

    # 4. [데이터 포장] 통계 딕셔너리 생성
    summary_stats = {
        'residents': total_residents,
        'supplies': total_supplies,
        'shelters': total_active_shelters,
        'assemblies': total_active_assemblies
    }
    
    return render_template('map.html', 
                           locations=locations, 
                           kakao_js_key=KAKAO_JS_KEY,
                           user_role=current_role,
                           summary=summary_stats,
                           incident_id=incident_id,
                           incident_title=inc.title)


@app.route('/api/map/refresh_data/<int:incident_id>')
def api_refresh_map_data(incident_id):
    """지도/대시보드에 필요한 최신 데이터를 JSON으로 반환"""
    
    # (A) 전체 통계 계산
    total_residents = 0
    total_active_shelters = 0
    total_active_assemblies = 0
    
    # 구호소 데이터 준비
    shelters = Shelter.query.filter_by(incident_id=incident_id).all()
    subq = select(func.max(ResidentLog.id))\
        .where(ResidentLog.status != 'NOTE')\
        .group_by(ResidentLog.resident_id)
    
    shelter_data = []
    for s in shelters:
        # 개별 구호소 인원 카운트
        res_count = ResidentLog.query.filter(
            ResidentLog.id.in_(subq),
            ResidentLog.shelter_id == s.id,
            ResidentLog.status == 'IN'
        ).count()
        
        staff_count = StaffLog.query.filter_by(shelter_id=s.id, logout_time=None).count()
        
        total_residents += res_count
        if s.is_active: total_active_shelters += 1
        
        shelter_data.append({
            'id': s.id, 'type': 'shelter', 'is_active': s.is_active,
            'stat_resident': res_count, 'stat_staff': staff_count
        })

    # 집결지 데이터 준비
    assemblies = AssemblyPoint.query.filter_by(incident_id=incident_id).all()
    assembly_data = []
    for a in assemblies:
        if a.is_active: total_active_assemblies += 1
        assembly_data.append({
            'id': a.id, 'type': 'assembly', 'is_active': a.is_active
        })

    # 물품 통계
    try:
        total_supplies = db.session.query(func.sum(Supply.quantity))\
        .join(Shelter).filter(Shelter.incident_id == incident_id).scalar() or 0
    except:
        total_supplies = 0

    return {
        'result': 'ok',
        'summary': {
            'residents': total_residents,
            'supplies': total_supplies,
            'shelters': total_active_shelters,
            'assemblies': total_active_assemblies
        },
        'locations': shelter_data + assembly_data
    }

# [New] 운영 상태 토글 API (관리자 전용)
@app.route('/api/map/toggle_status', methods=['POST'])
@login_required
def api_toggle_status():
    if session.get('role', 3) > 2: # Level 1, 2만 허용
        return {'result': 'fail', 'msg': '권한이 없습니다.'}

    try:
        data = request.json
        target_type = data.get('type')
        target_id = data.get('id')
        
        target_obj = None
        if target_type == 'shelter':
            target_obj = db.session.get(Shelter, target_id)
        elif target_type == 'assembly':
            target_obj = db.session.get(AssemblyPoint, target_id)
            
        if target_obj:
            # 상태 반전 (True <-> False)
            target_obj.is_active = not target_obj.is_active
            db.session.commit()
            
            broadcast_update()
            
            status_text = "운영 중" if target_obj.is_active else "운영 중지"
            return {'result': 'ok', 'msg': f'{status_text} 상태로 변경되었습니다.', 'new_status': target_obj.is_active}
        else:
            return {'result': 'fail', 'msg': '대상을 찾을 수 없습니다.'}

    except Exception as e:
        db.session.rollback()
        return {'result': 'error', 'msg': str(e)}

@app.route('/api/shelter/<int:shelter_id>/details')
@login_required
def api_get_shelter_details(shelter_id):
    """구호소 상세 현황 조회"""
    try:
        shelter = db.session.get(Shelter, shelter_id)
        if not shelter:
            return {'result': 'fail', 'msg': '구호소를 찾을 수 없습니다.'}
            
        residents_list = []
        inventory_list = []
        shelter_name_res = ""

        # [CASE 1] 전체 구호소 통합 조회 (shelter_id == 0)
        if shelter_id == 0:
            shelter_name_res = "전체 구호소 통합"
            
            subq = select(func.max(ResidentLog.id))\
                .where(ResidentLog.status != 'NOTE')\
                .group_by(ResidentLog.resident_id)
                
            residents_q = ResidentLog.query.filter(
                ResidentLog.id.in_(subq),
                ResidentLog.status == 'IN' # 이제 NOTE가 있어도 IN으로 인식됨
            ).order_by(ResidentLog.log_time.desc()).all()
            
            # 2. 전체 물품 재고 (구호소별 재고 합산)
            # shelter_id가 있는(배분된) 물품들의 합계
            try:
                supplies = db.session.query(
                    Supply.item_name, func.sum(Supply.quantity)
                ).filter(Supply.shelter_id != None).group_by(Supply.item_name).all()
                
                for item_name, total_qty in supplies:
                    inventory_list.append({'name': item_name, 'qty': total_qty})
            except:
                pass
        # [CASE 2] 개별 구호소 조회
        else:
            shelter = db.session.get(Shelter, shelter_id)
            if not shelter:
                return {'result': 'fail', 'msg': '구호소를 찾을 수 없습니다.'}
            
            shelter_name_res = shelter.name
            
            # 1. 해당 구호소 입소자
            subq = select(func.max(ResidentLog.id))\
                .where(ResidentLog.status != 'NOTE')\
                .group_by(ResidentLog.resident_id)
                
            residents_q = ResidentLog.query.filter(
                ResidentLog.id.in_(subq),
                ResidentLog.shelter_id == shelter_id,
                ResidentLog.status == 'IN'
            ).order_by(ResidentLog.log_time.desc()).all()
            
            # 2. 해당 구호소 물품
            try:
                supplies = Supply.query.filter_by(shelter_id=shelter_id).all()
                for item in supplies:
                    inventory_list.append({'name': item.item_name, 'qty': item.quantity})
            except:
                pass
                
        # [공통] 주민 리스트 변환 (소속 구호소 정보 포함)
        for r in residents_q:
            res = r.resident
            # r.shelter가 있으면 이름 가져오기
            sh_name = r.shelter.name if r.shelter else "알수없음"
            
            residents_list.append({
                'id': res.id,
                'incident_id': res.incident_id,
                'shelter_id': res.shelter_id,
                'name': res.name,
                'gender': res.gender,
                'age': res.age,
                'phone': res.phone,
                'note': res.note,
                'time': r.log_time.strftime('%m-%d %H:%M') if r.log_time else "",
                'shelter_name': sh_name # [New] 소속 구호소 이름 추가
            })

        # 근무자 명단
        staff_q = DutyOrder.query.filter_by(incident_id=shelter.incident_id, shelter_id=shelter_id).all()
        staff_list = []
        for s in staff_q:
            staff_list.append({
                'id': s.id, 
                'name': s.name, 
                'incident_id': s.incident_id,
                'shelter_id': s.shelter_id,
                'dept': s.dept, 
                'mission': s.mission
            })

        # 물품 재고 (Supply 모델이 있다고 가정, 없으면 빈 리스트)
        inventory_list = []
        try:
            supplies = Supply.query.filter_by(shelter_id=shelter_id).all()
            for item in supplies:
                inventory_list.append({'name': item.item_name, 'qty': item.quantity})
        except:
            pass # Supply 모델이 없으면 패스

        return {
            'result': 'ok',
            'name': shelter.name,
            'incident_id': shelter.incident_id,
            'id': shelter.id,
            'address': shelter.address or "",
            'capacity': getattr(shelter, 'capacity', 0), # 모델에 capacity가 없다면 0
            'lat': shelter.latitude,
            'lng': shelter.longitude,
            'residents': residents_list,
            'staff': staff_list,
            'inventory': inventory_list
        }
    except Exception as e:
        return {'result': 'error', 'msg': str(e)}
        


# ============================================================
# [NEW] 이재민 검색 API (모달용, 서버 페이징 + 최신 상태 기준)
# ============================================================
@app.route('/api/residents/search')
@login_required
def api_search_residents():
    try:
        # 1. 파라미터 수신
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 12, type=int) # 한 페이지당 카드 수
        current_status = request.args.get('status', 'IN')     # 탭 상태
        shelter_id = request.args.get('shelter_id', 0, type=int) # 0이면 전체
        search = request.args.get('search', '')

        # 2. 최신 로그 찾기 (서브쿼리)
        # 각 주민별로 가장 ID가 큰(최신) 로그를 찾습니다.
        subq = db.session.query(
            ResidentLog.resident_id, 
            func.max(ResidentLog.id).label('max_id')
        ).filter(ResidentLog.status != 'NOTE')\
         .group_by(ResidentLog.resident_id).subquery()

        # 3. 기본 쿼리 구성 (주민 + 최신로그 + 구호소)
        # 최신 로그(max_id)와 일치하는 기록만 조회 -> "현재 상태" 보장
        base_query = db.session.query(Resident, ResidentLog, Shelter).join(
            subq, Resident.id == subq.c.resident_id
        ).join(
            ResidentLog, ResidentLog.id == subq.c.max_id
        ).join(
            Shelter, ResidentLog.shelter_id == Shelter.id
        )

        # 4. 공통 필터 적용 (구호소, 검색어)
        # (이 필터는 리스트 조회와 카운트 조회 양쪽에 쓰입니다)
        if shelter_id != 0:
            base_query = base_query.filter(Shelter.id == shelter_id)
            
        if search:
            base_query = base_query.filter(
                (Resident.name.like(f'%{search}%')) | 
                (Resident.phone.like(f'%{search}%'))
            )

        # 5. 탭별 카운트 계산 (Status 필터 적용 전)
        # 검색 조건(구호소, 이름)에는 맞지만 상태는 다양한 사람들의 수를 셉니다.
        count_query = db.session.query(ResidentLog.status, func.count(ResidentLog.id)).select_from(Resident).join(
            subq, Resident.id == subq.c.resident_id
        ).join(
            ResidentLog, ResidentLog.id == subq.c.max_id
        ).join(
            Shelter, ResidentLog.shelter_id == Shelter.id
        )
        
        # 위에서 만든 필터 조건 재적용 (쿼리 객체가 다르므로 다시 적용)
        if shelter_id != 0: count_query = count_query.filter(Shelter.id == shelter_id)
        if search: count_query = count_query.filter((Resident.name.like(f'%{search}%')) | (Resident.phone.like(f'%{search}%')))
        
        status_counts_raw = count_query.group_by(ResidentLog.status).all()
        counts = {'IN': 0, 'HOSPITAL': 0, 'OUT': 0}
        for st, cnt in status_counts_raw:
            if st in counts: counts[st] = cnt

        # 6. 리스트 조회 (Status 필터 + 페이징 적용)
        final_query = base_query.filter(ResidentLog.status == current_status)
        pagination = final_query.order_by(ResidentLog.log_time.desc()).paginate(page=page, per_page=per_page, error_out=False)

        # 7. 데이터 변환
        residents_list = []
        for r, l, s in pagination.items:
            residents_list.append({
                'id': r.id,
                'incident_id': r.incident_id,
                'shelter_id': r.shelter_id,
                'name': r.name,
                'gender': r.gender,
                'age': r.age,
                'phone': r.phone,
                'note': r.note,
                'status': l.status,
                'time': l.log_time.strftime('%m-%d %H:%M') if l.log_time else "",
                'shelter_name': s.name
            })

        return {
            'result': 'ok',
            'list': residents_list,
            'counts': counts,
            'total_pages': pagination.pages,
            'current_page': page
        }

    except Exception as e:
        return {'result': 'error', 'msg': str(e)}
        
@app.route('/api/shelter/<int:shelter_id>/update', methods=['POST'])
@login_required
def api_update_shelter(shelter_id):
    if session.get('role', 3) > 2:
        return {'result': 'fail', 'msg': '권한이 없습니다.'}
    
    try:
        data = request.json
        shelter = db.session.get(Shelter, shelter_id)
        if not shelter:
            return {'result': 'fail', 'msg': '존재하지 않는 구호소입니다.'}
        
        # [New] 전달받은 필드가 있으면 업데이트
        if 'name' in data: shelter.name = data['name']
        if 'address' in data: shelter.address = data['address']
        if 'capacity' in data: shelter.capacity = int(data['capacity'])
        if 'lat' in data: shelter.latitude = float(data['lat'])
        if 'lng' in data: shelter.longitude = float(data['lng'])
        
        db.session.commit()
        broadcast_update() # 변경 알림
        
        return {'result': 'ok', 'msg': '정보가 수정되었습니다.'}
    except Exception as e:
        db.session.rollback()
        return {'result': 'error', 'msg': str(e)}
        
# ==========================================
# [API] 지도 상호작용 전용 (AJAX)
# ==========================================

@app.route('/api/map/add_node', methods=['POST'])
@login_required
def api_add_map_node():
    if session.get('role', 3) > 2: # 1, 2만 허용
        return {'result': 'fail', 'msg': '권한이 없습니다.'}
        
    try:
        data = request.json
        incident_id = data.get('incident_id') 
        node_type = data.get('type') 
        name = data.get('name')
        lat = data.get('lat')
        lng = data.get('lng')

        new_id = None # 생성된 ID 저장용

        if node_type == 'shelter':
            new_obj = Shelter(incident_id=incident_id, name=name, latitude=lat, longitude=lng, address="지도에서 지정됨", capacity=0, is_active=True)
            db.session.add(new_obj)
            db.session.flush() # ID 생성을 위해 flush
            new_id = new_obj.id
            
        elif node_type == 'assembly':
            new_obj = AssemblyPoint(incident_id=incident_id, name=name, latitude=lat, longitude=lng, address="지도에서 지정됨", is_active=True)
            db.session.add(new_obj)
            db.session.flush()
            new_id = new_obj.id
        else:
            return {'result': 'fail', 'msg': '잘못된 타입입니다.'}

        db.session.commit()
        
        broadcast_update()
        
        # [핵심] 생성된 ID를 함께 반환해야 프론트에서 바로 사용 가능
        return {'result': 'ok', 'msg': f'{name} 등록 완료', 'id': new_id}

    except Exception as e:
        db.session.rollback()
        return {'result': 'error', 'msg': str(e)}


@app.route('/api/map/connect', methods=['POST'])
@login_required
def api_connect_map_nodes():
    if session.get('role', 3) > 2: # 1, 2만 허용
        return {'result': 'fail', 'msg': '권한이 없습니다.'}
        
    try:
        
        data = request.json
        a_id = data.get('assembly_id')
        s_id = data.get('shelter_id')
        
        # 1. 중복 확인 (기존 로직 유지)
        exists = AssemblyDestination.query.filter_by(assembly_id=a_id, shelter_id=s_id).first()
        
        if exists:
            return {'result': 'fail', 'msg': '이미 연결되어 있습니다.'}
            
        now_points = AssemblyPoint.query.filter_by(id=a_id).first()
        now_incident = Incident.query.filter_by(id=now_points.incident_id).first()
        
        default_waypoints = ""
        if(now_incident.incident_type=="방사능"): 
            default_waypoints = "127.412678,36.385742|127.360745,36.359582"
            if(now_points.name=="한국원자력연구원"): default_waypoints = ""
        else:
            default_waypoints = ""
        
        if(now_points.name=="한국원자력연구원"): default_waypoints = ""

        # 2. 기본 경로 로직 (기존 로직 유지)
        waypoints = default_waypoints

        # 3. DB 저장 (기존 로직 유지)
        new_dest = AssemblyDestination(assembly_id=a_id, shelter_id=s_id, waypoints=waypoints)
        db.session.add(new_dest)
        db.session.commit()
        
        broadcast_update() # 변경 알림 전송

        # =========================================================
        # [추가됨] 즉시 경로를 그리기 위해 좌표 데이터 계산
        # =========================================================
        path_data = []
        
        # 좌표 조회를 위해 객체 가져오기
        assembly = db.session.get(AssemblyPoint, a_id)
        shelter = db.session.get(Shelter, s_id)
        
        if assembly and shelter:
            # 기존에 만들어둔 경로 탐색 함수(fetch_route_path) 활용
            path_data = fetch_route_path(
                f"{assembly.longitude},{assembly.latitude}", 
                f"{shelter.longitude},{shelter.latitude}", 
                waypoints or ""
            )

        # [핵심] waypoints 뿐만 아니라 계산된 path_data도 함께 반환
        return {
            'result': 'ok', 
            'msg': '연결되었습니다.', 
            'waypoints': waypoints, 
            'path_data': path_data  # <-- 이 데이터로 선을 그립니다
        }

    except Exception as e:
        db.session.rollback()
        return {'result': 'error', 'msg': str(e)}

@app.route('/api/supplies/add_hq', methods=['POST'])
@login_required
def api_add_hq_supply():
    if session.get('role', 3) > 2:
        return {'result': 'fail', 'msg': '권한이 없습니다.'}
    
    try:
        data = request.json
        item_name = data.get('item_name')
        qty = int(data.get('quantity', 0))
        
        if not item_name: return {'result': 'fail', 'msg': '품목명을 입력하세요.'}
        if qty <= 0: return {'result': 'fail', 'msg': '수량은 1개 이상이어야 합니다.'}

        # 본청(shelter_id=None)에 같은 이름의 물품이 있는지 확인
        hq_item = Supply.query.filter(Supply.shelter_id == None, Supply.item_name == item_name).first()
        
        if hq_item:
            # 이미 있으면 재고 추가 (입고)
            hq_item.quantity += qty
            msg = f"'{item_name}' 재고가 {qty}개 추가되었습니다. (총 {hq_item.quantity}개)"
        else:
            # 없으면 신규 등록
            new_item = Supply(shelter_id=None, item_name=item_name, quantity=qty)
            db.session.add(new_item)
            msg = f"'{item_name}' 품목이 신규 등록되었습니다."
            
        db.session.commit()
        broadcast_update() # 변경사항 전파
        
        return {'result': 'ok', 'msg': msg}
        
    except Exception as e:
        db.session.rollback()
        return {'result': 'error', 'msg': str(e)}
        
@app.route('/api/supplies/hq')
@login_required
def api_get_hq_supplies():
    """본청 재고 및 특정 사고의 구호소 목록 반환"""
    # 1. 화면(URL 파라미터)에서 incident_id를 먼저 받고, 없으면 세션에서 보조로 가져옴
    incident_id = request.args.get('incident_id')
    
    if not incident_id:
        return {'result': 'fail', 'msg': '사고 정보가 전송되지 않았습니다.'}

    # 본청 재고 조회
    supplies = Supply.query.filter(Supply.shelter_id == None).all()
    supply_data = [{'id': s.id, 'name': s.item_name, 'qty': s.quantity} for s in supplies]
    
    # 2. 전송받은 incident_id에 해당하는 구호소만 필터링
    shelters = Shelter.query.filter_by(incident_id=incident_id, is_active=True).all()
    shelter_list = [{'id': s.id, 'name': s.name} for s in shelters]
    
    return {'result': 'ok', 'supplies': supply_data, 'shelters': shelter_list}

# 3. 물품 배분 (본청 -> 구호소)
@app.route('/api/supplies/distribute', methods=['POST'])
@login_required
def api_distribute_supply():
    if session.get('role', 3) > 2:
        return {'result': 'fail', 'msg': '권한이 없습니다.'}
        
    data = request.json
    # JSON 바디에 포함된 incident_id 사용
    incident_id = data.get('incident_id')
    
    if not incident_id:
        return {'result': 'fail', 'msg': '사고 정보가 누락되었습니다.'}
    
    try:
        data = request.json
        item_name = data.get('item_name')
        qty = int(data.get('quantity'))
        target_shelter_id = data.get('target_id')
        
        #if qty <= 0: return {'result': 'fail', 'msg': '수량은 1 이상이어야 합니다.'}

        # 1. 본청 재고 확인 및 차감
        hq_item = Supply.query.filter(Supply.shelter_id == None, Supply.item_name == item_name).first()
        if not hq_item or hq_item.quantity < qty:
            return {'result': 'fail', 'msg': '본청 재고가 부족합니다.'}
        
        hq_item.quantity -= qty
        
        # 2. 해당 구호소에 재고 추가 (없으면 생성)
        target_item = Supply.query.filter_by(shelter_id=target_shelter_id, item_name=item_name).first()
        if target_item:
            target_item.quantity += qty
        else:
            new_item = Supply(shelter_id=target_shelter_id, item_name=item_name, quantity=qty)
            db.session.add(new_item)
            
            
        # 로그 기록 시 전달받은 incident_id 저장
        db.session.add(SupplyMovementLog(
            incident_id=incident_id,
            item_name=item_name,
            to_shelter_id=target_shelter_id,
            quantity=qty,
            staff_name=session.get('user_name')
        ))

        db.session.commit()
        broadcast_update()
        
        return {'result': 'ok', 'msg': f'{item_name} {qty}개를 배분했습니다.'}
        
    except Exception as e:
        db.session.rollback()
        return {'result': 'error', 'msg': str(e)}

        
# ==========================================
# [4] 구호소 관리 (Shelter)
# ==========================================
@app.route('/admin/shelter')
@login_required
def admin_shelter():
    """구호소 목록 조회 및 연결된 집결지 정보 확인 (ORM 적용)"""
    
    # 1. 모든 구호소 조회
    shelters_orm = Shelter.query.all()
    
    shelters = []
    for s in shelters_orm:
        # 템플릿 호환을 위해 객체를 딕셔너리로 변환
        sd = {
            'id': s.id,
            'name': s.name,
            'address': s.address,
            'phone': s.phone,
            'area': s.area,
            'capacity': s.capacity,
            'is_active': 1 if s.is_active else 0 # 템플릿에서 정수형 비교를 할 수 있으므로 변환
        }
        
        # [관계 활용] 구호소(s)와 연결된 집결지 목록 조회
        # models.py의 AssemblyDestination.target_shelter -> backref='assembly_sources' 활용
        matched = []
        for dest in s.assembly_sources:
            # dest는 AssemblyDestination 객체 -> dest.assembly_point로 집결지 접근
            ap = dest.assembly_point
            if ap and ap.is_active:
                matched.append({'id': ap.id, 'name': ap.name})
                
        sd['matched_assemblies'] = matched
        shelters.append(sd)
    
    # 2. 집결지 목록 (모달 내 선택용)
    all_assemblies_orm = AssemblyPoint.query.filter_by(is_active=True).all()
    all_assemblies = [{'id': a.id, 'name': a.name, 'address': a.address} for a in all_assemblies_orm]
    
    return render_template('admin_shelter.html', shelters=shelters, all_assemblies=all_assemblies)

@app.route('/shelter_detail/<int:shelter_id>')
@login_required
def shelter_detail(shelter_id):
    # AJAX용 JSON 응답 (ORM 사용)
    # 1. 입소자
    subq = db.session.query(func.max(ResidentLog.id)).group_by(ResidentLog.resident_id).subquery()
    logs = ResidentLog.query.filter(
        ResidentLog.id.in_(subq),
        ResidentLog.shelter_id == shelter_id,
        ResidentLog.status == 'IN'
    ).all()
    residents = [{'name': l.resident.name, 'gender': l.resident.gender, 'log_time': str(l.log_time)} for l in logs]
    
    # 2. 물품
    supplies = [{'item_name': s.item_name, 'quantity': s.quantity} for s in Supply.query.filter_by(shelter_id=shelter_id).all() if s.quantity > 0]
    
    # 3. 근무자
    staffs = [{'user_name': st.user_name, 'mission': st.mission, 'dept': st.dept, 'login_time': str(st.login_time)} for st in StaffLog.query.filter_by(shelter_id=shelter_id).order_by(StaffLog.login_time).all()]

    return {'residents': residents, 'supplies': supplies, 'staff': staffs}


@app.route('/add_shelter', methods=['POST'])
@login_required
def add_shelter():
    """신규 구호소 기본 정보 등록 (ORM 적용)"""
    name = request.form.get('name')
    try:
        if name:
            new_shelter = Shelter(
                name=name,
                address=request.form.get('address'),
                phone=request.form.get('phone'),
                area=request.form.get('area'),
                capacity=request.form.get('capacity'),
                is_active=True
            )
            db.session.add(new_shelter)
            db.session.commit()
            
            broadcast_update()
            
            app.logger.info(f"🏛️ 신규 구호소 등록: {name} (처리자: {session.get('user_name')})")
            
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"❌ 구호소 등록 실패 ({name}): {str(e)}")
        
    return redirect('/admin/shelter')


@app.route('/toggle_shelter/<int:shelter_id>/<int:current_status>')
@login_required
def toggle_shelter(shelter_id, current_status):
    """구호소 운영 상태(활성/비활성) 전환 (ORM 적용)"""
    try:
        #shelter = Shelter.query.get(shelter_id)
        shelter = db.session.get(Shelter, shelter_id)
        if shelter:
            # 1이면(활성) -> False(0)로, 0이면 -> True(1)로 전환
            shelter.is_active = False if current_status == 1 else True
            db.session.commit()
            
            broadcast_update()
            
            app.logger.info(f"🏛️ 구호소 상태 변경: {shelter.name} -> {shelter.is_active}")
            
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"❌ 상태 전환 오류: {str(e)}")
        
    return redirect('/admin/shelter')

# ==========================================
# [5] 라우트: 이재민 관리 (Resident)
# ==========================================
# ============================================================
# [NEW] 이재민 관리 API (입소 등록 - 가족 연결 포함)
# ============================================================
@app.route('/api/staff/register', methods=['POST'])
@login_required
def api_register_staff():
    if session.get('role', 3) > 2:
        return {'result': 'fail', 'msg': '권한이 없습니다.'}
        
    try:
        data = request.json
        incident_id = data.get('incident_id')
        shelter_id = data.get('shelter_id')
        name = data.get('name')
        
        if not incident_id or not shelter_id or not name:
            return {'result': 'fail', 'msg': '필수 정보가 누락되었습니다.'}

        # 근무자 등록
        new_staff = DutyOrder(
            incident_id=incident_id,
            shelter_id=shelter_id,
            name=name,
            phone=data.get('phone', ''),
            dept=data.get('dept', ''),
            mission=data.get('mission', '')
        )
        
        db.session.add(new_staff)
        db.session.commit()
        
        broadcast_update()
        
        # 알림 전송
        #shelter = db.session.get(Shelter, shelter_id)
        #send_sys_notification(f"👷 [{data.get('dept', '직원')}] {name}님이 {shelter.name} 근무를 시작했습니다.", shelter_id)
        
        return {'result': 'ok', 'msg': '근무 등록 완료'}
        
    except Exception as e:
        db.session.rollback()
        return {'result': 'error', 'msg': str(e)}
        
@app.route('/api/resident/register', methods=['POST'])
@login_required
def api_register_resident():
    try:
        data = request.json
        incident_id = data.get('incident_id')
        shelter_id = data.get('shelter_id')
        name = data.get('name')
        phone = data.get('phone', '')
        gender = data.get('gender', '미상')
        age = data.get('age', 0)
        note = data.get('note', '')
        
        # 가족 정보
        family_role = data.get('family_role', '세대주') # '세대주' or '세대원'
        head_phone = data.get('head_phone', '') # 세대원일 경우 입력받은 세대주 폰번호
        
        if not incident_id:
            return {'result': 'fail', 'msg': '사고 정보는 필수입니다.'}

        if not shelter_id or not name:
            return {'result': 'fail', 'msg': '이름과 구호소 정보는 필수입니다.'}

        # 1. 가족 ID 생성 또는 조회 logic
        family_id = None
        
        if family_role == '세대원':
            if not head_phone:
                return {'result': 'fail', 'msg': '세대원 등록 시 세대주 연락처가 필요합니다.'}
            
            # 세대주 찾기 (이름은 동명이인이 많으니 폰번호로 검색)
            head = Resident.query.filter_by(phone=head_phone, family_role='세대주').first()
            if not head:
                return {'result': 'fail', 'msg': f'연락처({head_phone})로 등록된 세대주를 찾을 수 없습니다.'}
            
            family_id = head.family_id
        else:
            # 세대주인 경우: 새로운 가족 ID 생성 (FAM-월일시분초)
            family_id = f"FAM-{datetime.now().strftime('%m%d%H%M%S')}"

        # 2. Resident 정보 생성 또는 업데이트
        # (중복 방지: 이름+연락처가 같으면 기존 사람으로 간주)
        resident = Resident.query.filter_by(name=name, phone=phone).first()
        
        if not resident:
            resident = Resident(
                incident_id = incident_id,
                shelter_id = shelter_id,
                name=name, 
                phone=phone, 
                gender=gender, 
                age=age, 
                note=note,
                family_id=family_id,
                family_role=family_role,
                village="현장등록"
            )
            db.session.add(resident)
            db.session.flush() # ID 생성을 위해 flush
        else:
            # 기존 정보 업데이트 (특이사항, 가족정보 등 갱신)
            resident.note = note
            resident.age = age
            resident.family_id = family_id
            resident.family_role = family_role

        # 3. ResidentLog(입소 기록) 생성
        # 이미 이 구호소에 'IN' 상태인지 확인
        active_log = ResidentLog.query.filter_by(resident_id=resident.id, incident_id = incident_id, shelter_id=shelter_id, status='IN').first()
        
        if active_log:
            return {'result': 'fail', 'msg': '이미 입소 중인 주민입니다.'}

        new_log = ResidentLog(
            resident_id=resident.id,
            incident_id = incident_id,
            shelter_id=shelter_id,
            status='IN',
            log_time=datetime.now()
        )
        db.session.add(new_log)
        db.session.commit()

        # 4. 알림 전송
        broadcast_update()
        
        # 구호소 이름 조회 (알림용)
        shelter = db.session.get(Shelter, shelter_id)
        send_sys_notification(f"📢 {name}님이 {shelter.name}에 입소 등록되었습니다.", incident_id, shelter_id, resident.id)
        
        return {'result': 'ok', 'msg': f'{name}님 입소 처리되었습니다.'}

    except Exception as e:
        db.session.rollback()
        return {'result': 'error', 'msg': str(e)}
        
# [NEW] 이재민 1명 상세 정보 조회 (AJAX용)
@app.route('/api/resident/<int:resident_id>/info')
@login_required
def api_get_resident_info(resident_id):
    try:
        resident = db.session.get(Resident, resident_id)
        if not resident:
            return {'result': 'fail', 'msg': '정보 없음'}

        # 1. 지급 이력 (최신순)
        dists = []
        for d in sorted(resident.distributions, key=lambda x: x.distributed_at, reverse=True):
            dists.append({
                'id': d.id,  # [추가] 삭제용 ID
                'item_name': d.supply.item_name,
                'qty': d.quantity,
                'time': d.distributed_at.strftime('%m-%d %H:%M')
            })

        # 2. 입퇴소 이력 조회 (최신순)
        history = []
        logs = sorted(resident.logs, key=lambda x: x.log_time, reverse=True)
        for log in logs:
            history.append({
                'id': log.id,
                'status': log.status,
                'shelter_name': log.shelter.name,
                'content': log.log_content,  # [추가] 텍스트 내용 포함
                'time': log.log_time.strftime('%m-%d %H:%M')
            })

        # 3. 현재 머물고 있는 구호소의 물품 재고 조회
        shelter_supplies = []
        last_log = logs[0] if logs else None
        
        if last_log and last_log.status == 'IN':
            current_shelter_id = last_log.shelter_id
            supplies = Supply.query.filter(
                Supply.shelter_id == current_shelter_id, 
                Supply.quantity > 0
            ).all()
            shelter_supplies = [{'id': s.id, 'name': s.item_name, 'qty': s.quantity} for s in supplies]

        return {
            'result': 'ok',
            'id': resident.id,
            'incident_id': resident.incident_id,
            'shelter_id': resident.shelter_id,
            'name': resident.name,
            'gender': resident.gender,
            'age': resident.age,
            'phone': resident.phone,
            'family_role': resident.family_role,
            'note': resident.note,
            'distributions': dists,
            'history': history,
            'shelter_supplies': shelter_supplies
        }
    except Exception as e:
        return {'result': 'error', 'msg': str(e)}

# 2. [NEW] 특이사항 텍스트 기록 API (app.py 적절한 곳에 추가)
@app.route('/api/resident/note/add', methods=['POST'])
@login_required
def api_add_resident_note():
    try:
        data = request.json
        incident_id = data.get('incident_id')
        resident_id = data.get('resident_id')
        shelter_id = data.get('shelter_id')
        content = data.get('content')

        if not content:
            return {'result': 'fail', 'msg': '내용을 입력해주세요.'}

        # 특이사항 로그 생성 (status='NOTE')
        new_log = ResidentLog(
            incident_id=incident_id,
            resident_id=resident_id,
            shelter_id=shelter_id,
            status='NOTE',  # 상태값을 'NOTE'로 저장
            log_content=content,
            log_time=datetime.now()
        )
        db.session.add(new_log)
        db.session.commit()
        
        # broadcast_update() # 필요시 전체 갱신 (단순 메모는 생략 가능)
        
        return {'result': 'ok', 'msg': '기록되었습니다.'}

    except Exception as e:
        db.session.rollback()
        return {'result': 'error', 'msg': str(e)}
        
        
@app.route('/api/staff/delete', methods=['POST'])
@login_required
def api_delete_staff():
    # 관리자(Level 1, 2)만 삭제 가능하도록 권한 체크
    if session.get('role', 3) > 2:
        return {'result': 'fail', 'msg': '권한이 없습니다.'}

    try:
        staff_id = request.json.get('id')
        # 근무 명령(DutyOrder) 조회
        staff = db.session.get(DutyOrder, staff_id)
        
        if not staff:
            return {'result': 'fail', 'msg': '근무자 정보를 찾을 수 없습니다.'}

        db.session.delete(staff)
        db.session.commit()
        
        #broadcast_update() # 지도/대시보드 갱신 알림
        return {'result': 'ok', 'msg': '근무자가 삭제되었습니다.'}
        
    except Exception as e:
        db.session.rollback()
        return {'result': 'error', 'msg': str(e)}
        
        
# [NEW] 물품 지급 내역 삭제 API (지도 패널용 AJAX)
@app.route('/api/dist_log/delete', methods=['POST'])
@login_required
def api_delete_distribution_log():
    try:
        log_id = request.json.get('id')
        log = db.session.get(DistributionLog, log_id)
        
        if not log:
            return {'result': 'fail', 'msg': '기록을 찾을 수 없습니다.'}

        # 재고 복구
        if log.supply:
            log.supply.quantity += log.quantity
        
        db.session.delete(log)
        db.session.commit()
        
        broadcast_update()
        return {'result': 'ok', 'msg': '지급이 취소되고 재고가 복구되었습니다.'}
        
    except Exception as e:
        db.session.rollback()
        return {'result': 'error', 'msg': str(e)}
        
        
# [NEW] 상태 변경 이력 삭제 API (지도 패널용 AJAX)
@app.route('/api/status_log/delete', methods=['POST'])
@login_required
def api_delete_status_log():
    try:
        log_id = request.json.get('id')
        log = db.session.get(ResidentLog, log_id)
        
        if not log:
            return {'result': 'fail', 'msg': '기록을 찾을 수 없습니다.'}
            
        db.session.delete(log)
        db.session.commit()
        
        broadcast_update()
        return {'result': 'ok', 'msg': '이력이 삭제되었습니다.'}
        
    except Exception as e:
        db.session.rollback()
        return {'result': 'error', 'msg': str(e)}
        
# ============================================================
# [UPDATE] 상태 변경 API (재입소/퇴소 로직 분리)
# ============================================================
@app.route('/api/resident/status', methods=['POST'])
@login_required
def api_update_resident_status():
    try:
        data = request.json
        incident_id = data.get('incident_id')
        resident_id = data.get('resident_id')
        shelter_id = data.get('shelter_id')
        new_status = data.get('status')

        if not resident_id or not new_status:
            return {'result': 'fail', 'msg': '잘못된 요청입니다.'}

        # 정보 조회
        resident = db.session.get(Resident, resident_id)
        shelter = db.session.get(Shelter, shelter_id)
        r_name = resident.name if resident else "주민"
        s_name = shelter.name if shelter else "구호소"

        msg_action = ""

        # ---------------------------------------------------------
        # [CASE 1] 복귀 (재입소) 요청
        # ---------------------------------------------------------
        if new_status == 'IN':
            # [수정] 단순히 'IN'이 있는지 찾는 게 아니라, '가장 최신 기록'이 'IN'인지 확인
            last_log = ResidentLog.query.filter_by(
                incident_id=incident_id,
                resident_id=resident_id, 
                shelter_id=shelter_id
            ).order_by(ResidentLog.id.desc()).first()
            
            # 최신 기록이 존재하고, 그 상태가 이미 'IN'이라면 중복 입소로 차단
            if last_log and last_log.status == 'IN':
                return {'result': 'fail', 'msg': f'{r_name}님은 현재 입소 중인 상태입니다.'}

            # 문제 없으면 새로운 입소 로그 생성
            new_log = ResidentLog(
                incident_id=incident_id,
                resident_id=resident_id,
                shelter_id=shelter_id,
                status='IN',
                log_time=datetime.now()
            )
            db.session.add(new_log)
            msg_action = "구호소 복귀(재입소)"

        # ---------------------------------------------------------
        # [CASE 2] 퇴소 / 병원 이송 요청
        # ---------------------------------------------------------
        else:
            # 퇴소 처리할 때는 '가장 최근의 입소(IN) 기록'을 찾아서 종료시킴
            # (혹시 과거 데이터가 꼬여 있어도, 최신 기록을 우선적으로 처리)
            log = ResidentLog.query.filter_by(
                incident_id=incident_id,
                resident_id=resident_id, 
                shelter_id=shelter_id, 
                status='IN'
            ).order_by(ResidentLog.id.desc()).first()

            if not log:
                return {'result': 'fail', 'msg': '현재 입소 중인 정보가 없어 상태를 변경할 수 없습니다.'}

            new_log = ResidentLog(
                incident_id=incident_id,
                resident_id=resident_id,
                shelter_id=shelter_id,
                status=new_status,
                log_time=datetime.now()
            )
            db.session.add(new_log)
            msg_action = "퇴소(귀가)" if new_status == 'OUT' else "병원 이송"

        # ---------------------------------------------------------
        # [공통] 반영
        # ---------------------------------------------------------
        db.session.commit()
        broadcast_update()
        
        noti = f"📢 {r_name}님이 {s_name}에서 {msg_action} 처리되었습니다."
        send_sys_notification(noti, incident_id, shelter_id, resident_id)

        return {'result': 'ok', 'msg': f'{msg_action} 처리되었습니다.'}

    except Exception as e:
        db.session.rollback()
        return {'result': 'error', 'msg': str(e)}

@app.route('/admin/resident')
@login_required
def admin_resident():
    page = request.args.get('page', 1, type=int)
    per_page = 10
    status_filter = request.args.get('status', 'IN')
    search = request.args.get('search', '')
    shelter_filter = request.args.get('shelter_id') or session.get('shelter_id')

    # Subquery for latest log
    subq = db.session.query(
        ResidentLog.resident_id, 
        func.max(ResidentLog.id).label('max_id')
    ).filter(ResidentLog.status != 'NOTE')\
     .group_by(ResidentLog.resident_id).subquery()

    # Base Query
    query = db.session.query(Resident, ResidentLog, Shelter).join(
        subq, Resident.id == subq.c.resident_id
    ).join(
        ResidentLog, ResidentLog.id == subq.c.max_id
    ).join(
        Shelter, ResidentLog.shelter_id == Shelter.id
    )

    # Filtering
    query = query.filter(ResidentLog.status == status_filter)
    
    if search:
        query = query.filter(
            (Resident.name.like(f'%{search}%')) | (Resident.phone.like(f'%{search}%'))
        )
    if shelter_filter:
        query = query.filter(Shelter.id == shelter_filter)

    # Sorting & Pagination
    pagination = query.order_by(
        ResidentLog.log_time.desc(), Resident.family_id.desc()
    ).paginate(page=page, per_page=per_page)

    # Data formatting for template
    residents_list = []
    for r, l, s in pagination.items:
        # 물품 수령 내역 (Group Concat 대체 -> Python 로직)
        dist_items = []
        for d in r.distributions:
            dist_items.append(f"{d.supply.item_name}:{d.quantity}:{d.id}")
        
        residents_list.append({
            'id': r.id, 'name': r.name, 'phone': r.phone,
            'gender': r.gender, 'age': r.age,
            'shelter_id': s.id, 'shelter_name': s.name,
            'received_items': ",".join(dist_items),
            'family_id': r.family_id, 'family_role': r.family_role
        })

    # Supplies for dropdown
    shelter_supplies = {}
    supplies = Supply.query.filter(Supply.quantity > 0, Supply.shelter_id != None).all()
    for sup in supplies:
        if sup.shelter_id not in shelter_supplies: shelter_supplies[sup.shelter_id] = []
        shelter_supplies[sup.shelter_id].append({'id': sup.id, 'name': sup.item_name, 'quantity': sup.quantity})

    all_shelters = Shelter.query.filter_by(is_active=True).all()
    # 템플릿 호환을 위해 튜플 리스트로 변환
    all_shelters_list = [(s.id, s.name) for s in all_shelters]

    return render_template('admin_resident.html', residents=residents_list, 
                           shelter_supplies=shelter_supplies, all_shelters_list=all_shelters_list,
                           current_status=status_filter, current_shelter=shelter_filter,
                           search_keyword=search, page=page, total_pages=pagination.pages)

        
@app.route('/add_resident_admin', methods=['POST'])
@login_required
def add_resident_admin():
    try:
        family_role = request.form.get('family_role', '세대주')
        head_phone = request.form.get('head_phone')
        
        # 가족 ID 로직
        family_id = f"FAM-{datetime.now().strftime('%m%d%H%M%S')}"
        if family_role == '세대원' and head_phone:
            head = Resident.query.filter_by(phone=head_phone).first()
            if head: family_id = head.family_id

        new_res = Resident(
            name=request.form.get('name'),
            phone=request.form.get('phone'),
            gender=request.form.get('gender'),
            age=request.form.get('age'),
            village=request.form.get('village'),
            family_id=family_id,
            family_role=family_role
        )
        db.session.add(new_res)
        db.session.flush() # ID 생성

        shelter_id = request.form.get('shelter_id')
        log = ResidentLog(resident_id=new_res.id, shelter_id=shelter_id, status="IN")
        db.session.add(log)
        db.session.commit()
        
        broadcast_update()

        # 알림
        #shelter = Shelter.query.get(shelter_id)
        shelter = db.session.get(Shelter, shelter_id)
        msg = f"{new_res.name}님이 {shelter.name}에 입소하였습니다."
        send_sys_notification(msg, shelter_id, new_res.id)
        #flash(f"✅ {new_res.name}님 등록 완료")

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"주민 등록 실패: {e}")
        flash("❌ 등록 중 오류 발생")

    return redirect('/admin/resident')


@app.route('/add_resident', methods=['POST'])
def add_resident():
    # 사용자(QR) 직접 등록
    try:
        shelter_id = request.form.get('shelter_id')
        is_new = request.form.get('is_new_family')
        p_fam_id = request.form.get('parent_family_id')
        
        fam_id = f"FAM-{datetime.now().strftime('%m%d%H%M%S')}"
        fam_role = "세대주"
        if is_new != 'on' and p_fam_id:
            fam_id = p_fam_id
            fam_role = "세대원"

        res = Resident(
            name=request.form.get('name'),
            phone=request.form.get('phone'),
            village=request.form.get('village'),
            gender=request.form.get('gender'),
            age=request.form.get('age'),
            note=request.form.get('note'),
            family_id=fam_id,
            family_role=fam_role
        )
        db.session.add(res)
        db.session.flush()
        
        db.session.add(ResidentLog(resident_id=res.id, shelter_id=shelter_id, status='IN'))
        db.session.commit()
        
        broadcast_update()

        #shelter = Shelter.query.get(shelter_id)
        shelter = db.session.get(Shelter, shelter_id)
        msg = f"{res.name}님이 {shelter.name}에 입소하였습니다."
        send_sys_notification(msg, shelter_id, res.id)
        
        return redirect(url_for('user_info', resident_id=res.id))
        
    except ValueError as ve:
        # [입력 오류 처리]
        db.session.rollback() # 필수
        flash(f"입력 오류: {str(ve)}", "warning") # 노란색 경고
        return redirect(request.referrer or '/') # 이전 페이지로

    except Exception as e:
        # [시스템 오류 처리]
        db.session.rollback() # 필수: DB가 락 걸리는 것 방지
        app.logger.error(f"이재민 등록 실패: {e}") # 서버 로그엔 남김
        flash("등록 중 시스템 오류가 발생했습니다. 관리자에게 문의하세요.", "error") # 빨간색 에러
        return redirect(request.referrer or '/')


@app.route('/resident_manage/<int:resident_id>')
@login_required
def resident_manage(resident_id):
    # [수정 1] 경고 해결을 위해 db.session.get 사용
    res = db.session.get(Resident, resident_id)
    if not res:
        return render_template('errors/404.html'), 404

    # [수정 2] 로그 정렬 로직 수정 (핵심)
    # 현재: [과거 -> 최신] 순서라 loop.last가 최신 기록이 됨
    # 변경: sorted(..., reverse=True)로 [최신 -> 과거] 순서로 정렬
    # 결과: 템플릿의 loop.last가 '가장 오래된 기록(최초기록)'이 되어 정상 표시됨
    sorted_logs = sorted(res.logs, key=lambda x: x.log_time, reverse=True)
    
    # 정렬된 로그로 리스트 생성
    status_logs = [(l.status, l.shelter.name, str(l.log_time), l.id) for l in sorted_logs]
    
    last_log = sorted_logs[0] if sorted_logs else None # 최신 로그가 0번 인덱스
    shelter_id = last_log.shelter_id if last_log else None
    
    # 지급 이력도 최신순 정렬 권장
    sorted_dists = sorted(res.distributions, key=lambda x: x.distributed_at, reverse=True)
    dist_logs = [(d.supply.item_name, d.quantity, str(d.distributed_at), d.id) for d in sorted_dists]
    
    # 현재 구호소 물품
    shelter_supplies = []
    if shelter_id:
        supplies = Supply.query.filter_by(shelter_id=shelter_id).all()
        shelter_supplies = [{'id':s.id, 'name':s.item_name, 'quantity':s.quantity} for s in supplies if s.quantity > 0]

    res_data = (res.id, res.name, res.phone, res.village, res.gender, res.age, res.note, 
                last_log.shelter.name if last_log else "", last_log.status if last_log else "", shelter_id)
                
    #broadcast_update()

    return render_template('resident_manage.html', res=res_data, supplies=shelter_supplies, 
                           dist_logs=dist_logs, status_logs=status_logs)


def process_status_change(res_id, sh_id, status, user_name):
    """상태 변경, 로그 기록, 알림 전송 통합 (ORM 적용)"""
    try:
        #resident = Resident.query.get(res_id)
        #shelter = Shelter.query.get(sh_id)
        resident = db.session.get(Resident, res_id)
        shelter = db.session.get(Shelter, sh_id)
        
        res_name = resident.name if resident else "알 수 없는 주민"
        sh_name = shelter.name if shelter else "알 수 없는 구호소"

        status_msg = {
            'IN': f"{res_name}님이 {sh_name}으로 복귀하였습니다.",
            'OUT': f"{res_name}님이 {sh_name}에서 퇴소하였습니다.",
            'HOSPITAL': f"{res_name}님이 {sh_name}에서 병원으로 이송되었습니다."
        }.get(status, f"{res_name}님의 상태가 {status}로 변경되었습니다.")

        # 로그 생성
        new_log = ResidentLog(
            resident_id=res_id, shelter_id=sh_id, status=status, log_time=datetime.now()
        )
        db.session.add(new_log)
        db.session.commit()
        
        broadcast_update()

        app.logger.info(f"🔄 {status} 변경: {res_name} (처리: {user_name})")
        send_sys_notification(status_msg, sh_id, res_id)
        return status_msg
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"상태 변경 오류: {e}")
        raise e


@app.route('/update_status/<target>/<int:res_id>/<int:sh_id>/<status>')
@login_required
def update_status_router(target, res_id, sh_id, status):
    process_status_change(res_id, sh_id, status, session.get('user_name'))
    broadcast_update()
    if target == 'manage':
        return redirect(url_for('resident_manage', resident_id=res_id))
    elif target == 'shelter':
        return redirect('/admin/shelter')
    return redirect('/admin/resident')


@app.route('/user_info/<int:resident_id>')
def user_info(resident_id):
    # 최근 로그 기준 정보
    last_log = ResidentLog.query.filter_by(resident_id=resident_id).order_by(ResidentLog.id.desc()).first()
    if last_log:
        r = last_log.resident
        s = last_log.shelter
        data = {'id': r.id, 'name': r.name, 'shelter_name': s.name, 'address': s.address, 'phone': s.phone}
        return render_template('user_info.html', resident=data)
    return "정보 없음", 404


@app.route('/register/<int:shelter_id>')
# @login_required  <-- [중요] 신규 입소자는 로그인 상태가 아니므로 이 줄을 삭제하거나 주석 처리해야 합니다.
def user_register(shelter_id):
    """주민용: 특정 구호소 입소 등록 페이지(QR연결용) - ORM 적용"""
    try:
        # 1. 구호소 조회 (ORM 사용)
        shelter = db.session.get(Shelter, shelter_id)
        
        # 2. 구호소가 존재하지 않는 경우 처리
        if not shelter:
            # 아까 만든 예쁜 404 페이지 활용
            return render_template('errors/404.html'), 404

        # 3. 템플릿 렌더링
        return render_template(
            'user_registration.html', 
            shelter_id=shelter_id, 
            shelter_name=shelter.name
        )

    except Exception as e:
        app.logger.error(f"입소 페이지 접근 오류: {e}")
        return render_template('errors/500.html'), 500


@app.route('/admin/resident/export_excel')
@login_required
def export_resident_excel():
    """
    모든 이재민 정보를 엑셀로 내보내기 (ORM 적용)
    - 기본 정보, 현재 상태
    - 이동 이력 (History)
    - 물품 수령 내역 (Supplies)
    """
    if session.get('role') != 1:  # 관리자만 가능
        return "권한이 없습니다.", 403

    # 1. 최신 상태(Current Status)를 구하기 위한 Subquery
    # (resident_id 별로 가장 큰 id를 가진 로그를 찾음)
    subq = db.session.query(
        ResidentLog.resident_id,
        func.max(ResidentLog.id).label('max_id')
    ).group_by(ResidentLog.resident_id).subquery()

    # 2. 전체 이재민 + 최신 로그 + 구호소 정보 조회
    # (SQLAlchemy의 Query 객체 사용)
    query = db.session.query(Resident, ResidentLog, Shelter).join(
        subq, Resident.id == subq.c.resident_id
    ).join(
        ResidentLog, ResidentLog.id == subq.c.max_id
    ).join(
        Shelter, ResidentLog.shelter_id == Shelter.id
    ).order_by(Resident.name)

    results = query.all()

    # 엑셀에 담을 데이터 리스트
    export_data = []

    for r, l, s in results:
        # -------------------------------------------------
        # [A] 이동 이력 (History) 가공
        # models.py의 relationship(backref='resident') 덕분에 r.logs로 접근 가능
        # -------------------------------------------------
        history_text_list = []
        # 시간순 정렬
        sorted_logs = sorted(r.logs, key=lambda x: x.log_time)
        
        for log in sorted_logs:
            time_str = log.log_time.strftime('%m-%d %H:%M')
            status_kor = {'IN': '입소', 'OUT': '퇴소', 'HOSPITAL': '병원이송'}.get(log.status, log.status)
            # log.shelter.name으로 접근 (N+1 문제가 있지만, 관리자용 기능이라 허용 범위)
            history_text_list.append(f"[{time_str}] {status_kor}({log.shelter.name})")
        
        full_history = "\n".join(history_text_list) # 셀 내 줄바꿈

        # -------------------------------------------------
        # [B] 물품 수령 내역 가공
        # r.distributions 로 접근하여 파이썬에서 합계 계산
        # -------------------------------------------------
        supply_dict = {}
        for dist in r.distributions:
            item_name = dist.supply.item_name
            if item_name not in supply_dict:
                supply_dict[item_name] = 0
            supply_dict[item_name] += dist.quantity
        
        supply_text_list = [f"{k}({v})" for k, v in supply_dict.items()]
        full_supplies = ", ".join(supply_text_list)

        # -------------------------------------------------
        # [C] 데이터 취합
        # -------------------------------------------------
        export_data.append({
            '이름': r.name,
            '연락처': r.phone,
            '성별': r.gender,
            '나이': r.age,
            '마을(거주지)': r.village,
            '가족ID': r.family_id,
            '가족구분': r.family_role,
            '특이사항': r.note,
            '현재위치': s.name, # query에서 join된 최신 구호소 정보
            '현재상태': {'IN': '입소중', 'OUT': '퇴소', 'HOSPITAL': '병원'}.get(l.status, l.status),
            '이동 이력 (전체)': full_history,
            '수령 물품 내역': full_supplies
        })

    # 3. Pandas DataFrame 생성 및 엑셀 변환
    df = pd.DataFrame(export_data)
    
    output = BytesIO()
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        df.to_excel(writer, index=False, sheet_name='이재민현황')
        
        # (옵션) 열 너비 자동 조정 등을 추가할 수 있음
        # worksheet = writer.sheets['이재민현황']

    output.seek(0)
    filename = f"resident_export_{datetime.now().strftime('%Y%m%d_%H%M')}.xlsx"
    
    return send_file(
        output,
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        as_attachment=True,
        download_name=filename
    )

# ==========================================
# [6] 라우트: 물품 및 기타 관리 (Supply, Shelter)
# ==========================================
@app.route('/admin/supply')
@login_required
def admin_supply():
    """본부 재고 현황 및 구호소별 배분 현황 조회 (안전한 JOIN 쿼리 적용)"""
    
    # 1. 본부 재고 (shelter_id가 NULL인 것)
    hq_supplies = Supply.query.filter(Supply.shelter_id == None).all()
    # 템플릿 호환용 튜플 리스트 변환 (ID, 이름, 수량)
    hq_list = [(h.id, h.item_name, h.quantity) for h in hq_supplies]
    
    # 2. 구호소별 보유 재고
    shelter_stocks = {}
    # Shelter 정보와 함께 조회
    ss = db.session.query(Supply, Shelter).join(Shelter).filter(Supply.shelter_id != None).order_by(Shelter.name).all()
    
    for supply, shelter in ss:
        if shelter.name not in shelter_stocks:
            shelter_stocks[shelter.name] = {'id': shelter.id, 'items': []}
        shelter_stocks[shelter.name]['items'].append({
            'name': supply.item_name, 
            'qty': supply.quantity, 
            'supply_id': supply.id
        })
        
    # 3. [핵심 수정] 배분 이력 조회 (N+1 문제 해결 및 에러 방지)
    # SupplyMovementLog와 Shelter를 Outer Join하여 구호소가 삭제되어도 로그는 보이게 함
    results = db.session.query(SupplyMovementLog, Shelter)\
        .outerjoin(Shelter, SupplyMovementLog.to_shelter_id == Shelter.id)\
        .order_by(SupplyMovementLog.moved_at.desc()).all()
    
    history_list = []
    for log, shelter in results:
        # 구호소가 없으면 '알 수 없음' 처리하여 에러 방지
        sh_name = shelter.name if shelter else "삭제된 구호소(알수없음)"
        # 템플릿 호환 튜플: (품목, 수량, 구호소명, 일시, 담당자)
        history_list.append((log.item_name, log.quantity, sh_name, str(log.moved_at), log.staff_name))
    
    # 4. 구호소 목록 (드롭다운용)
    all_shelters = Shelter.query.filter_by(is_active=True).all()
    all_shelters_list = [(s.id, s.name) for s in all_shelters]

    return render_template('admin_supply.html', 
                           hq_supplies=hq_list, 
                           shelter_stocks=shelter_stocks, 
                           move_history=history_list, 
                           all_shelters_list=all_shelters_list)


@app.route('/allocate_supply', methods=['POST'])
@login_required
def allocate_supply():
    try:
        s_id = request.form.get('supply_id')
        t_id = request.form.get('target_shelter_id') # 구호소 ID
        qty = int(request.form.get('quantity', 0))

        # [유효성 검사 1] 구호소를 선택하지 않은 경우 방어
        if not t_id:
            flash("❌ 배분할 대상 구호소를 선택해주세요.")
            return redirect('/admin/supply')
            

        # 데이터 조회 및 처리
        #src = Supply.query.get(s_id)
        src = db.session.get(Supply, s_id)
        if src and src.quantity >= qty:
            # 1. 본부 재고 차감
            src.quantity -= qty
            
            # 2. 대상 구호소에 해당 물품이 있는지 확인 후 처리
            tgt = Supply.query.filter_by(shelter_id=t_id, item_name=src.item_name).first()
            if tgt:
                tgt.quantity += qty
            else:
                # 없으면 신규 생성
                db.session.add(Supply(shelter_id=t_id, item_name=src.item_name, quantity=qty))
            
            # 3. 이동 로그 기록 (FK 오류 방지를 위해 shelter_id를 int로 변환)
            db.session.add(SupplyMovementLog(
                item_name=src.item_name, 
                to_shelter_id=int(t_id), 
                quantity=qty, 
                moved_at=datetime.now(), 
                staff_name=session.get('user_name')
            ))
            
            db.session.commit()
            
            # 4. 완료 메시지 및 알림
            #target_shelter = Shelter.query.get(t_id)
            target_shelter = db.session.get(Shelter, t_id)
            sh_name = target_shelter.name if target_shelter else "구호소"
            msg = f"🚚 {sh_name}에 {src.item_name} {qty}개가 배분되었습니다."
            
            send_sys_notification(msg, t_id)
            flash(f"✅ {msg}")
            
        else:
            flash("❌ 본부 재고가 부족합니다.")

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"물품 배분 오류: {e}")
        flash("❌ 처리 중 시스템 오류가 발생했습니다.")
        
    return redirect('/admin/supply')


@app.route('/add_supply', methods=['POST'])
@login_required
def add_supply():
    """본부 신규 물품(공통 재고) 등록 (ORM 적용)"""
    try:
        item_name = request.form.get('item_name')
        quantity = int(request.form.get('quantity', 0))

        # 1. 이미 등록된 물품명인지 확인 (본부 재고: shelter_id IS NULL)
        existing_supply = Supply.query.filter_by(item_name=item_name, shelter_id=None).first()

        if existing_supply:
            # 이미 있으면 수량만 추가
            existing_supply.quantity += quantity
            flash(f"✅ 기존 '{item_name}' 재고에 {quantity}개가 추가되었습니다.")
        else:
            # 없으면 신규 생성
            new_supply = Supply(
                item_name=item_name,
                quantity=quantity,
                shelter_id=None  # 본부 재고임
            )
            db.session.add(new_supply)
            flash(f"✅ 신규 물품 '{item_name}'이(가) 등록되었습니다.")

        db.session.commit()
        broadcast_update()
        app.logger.info(f"📦 물품 등록/입고: {item_name} (+{quantity}) by {session.get('user_name')}")

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"❌ 물품 등록 실패: {str(e)}")
        flash("❌ 물품 등록 중 오류가 발생했습니다.")

    return redirect('/admin/supply')


@app.route('/add_inventory/<int:sup_id>', methods=['POST'])
@login_required
def add_inventory(sup_id):
    """기존 물품의 수량 입고 또는 조정 (ORM 적용)"""
    try:
        qty = request.form.get('quantity', 0, type=int)
        
        if qty != 0:
            # [수정] Supply.query.get_or_404(sup_id) -> db.session.get 사용
            supply = db.session.get(Supply, sup_id)
            if not supply:
                flash("❌ 물품을 찾을 수 없습니다.")
                return redirect('/admin/supply')
            
            supply.quantity += qty
            db.session.commit()
            
            broadcast_update()
            
            action = "입고" if qty > 0 else "조정(차감)"
            app.logger.info(f"📦 물품 {action}: {supply.item_name} (ID:{sup_id}, 변동:{qty}) by {session.get('user_name')}")
            
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"❌ 재고 조정 실패: {str(e)}")
        flash("❌ 재고 조정 중 오류가 발생했습니다.")

    return redirect('/admin/supply')


@app.route('/distribute', methods=['POST'])
@login_required
def distribute():
    res_id = request.form.get('res_id')
    sup_id = request.form.get('sup_id')
    try:
        #supply = Supply.query.get(sup_id)
        supply = db.session.get(Supply, sup_id)
        if supply and supply.quantity > 0:
            supply.quantity -= 1
            log = DistributionLog(resident_id=res_id, supply_id=sup_id, quantity=1)
            db.session.add(log)
            db.session.commit()
            
            broadcast_update()
            app.logger.info(f"물품 지급: {res_id} <- {supply.item_name}")
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"지급 실패: {e}")
    
    return redirect('/admin/resident')

@app.route('/manage_distribute', methods=['POST'])
@login_required
def manage_distribute():
    """이재민 상세 페이지에서 물품 1개 지급 (ORM 적용)"""
    incident_id = request.form.get('incident_id')
    res_id = request.form.get('res_id')
    sup_id = request.form.get('sup_id')
    quantity = int(request.form.get('quantity', 1)) # 기본값 1

    try:
        # 1. 물품 조회 (SQLAlchemy 2.0 권장 방식)
        supply = db.session.get(Supply, sup_id)
        
        if not supply:
            flash("존재하지 않는 물품입니다.", "error")
            return redirect(url_for('resident_manage', resident_id=res_id))

        # 2. 재고 확인
        if supply.quantity < quantity:
            flash(f"재고가 부족합니다. (현재: {supply.quantity}개)", "warning")
            return redirect(url_for('resident_manage', resident_id=res_id))

        # 3. 지급 처리 (재고 차감)
        supply.quantity -= quantity
        
        # 4. 로그 생성
        new_log = DistributionLog(
            incident_id=incident_id,
            resident_id=res_id,
            supply_id=sup_id,
            quantity=quantity
        )
        db.session.add(new_log)
        db.session.commit()
        
        broadcast_update()
        
        # 5. 성공 알림
        flash(f"{supply.item_name} {quantity}개를 지급했습니다.", "success")
        
        # (선택 사항) 시스템 알림 전송 로직이 있다면 여기에 추가
        # send_sys_notification(...)

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"물품 지급 오류: {e}")
        flash("지급 처리 중 시스템 오류가 발생했습니다.", "error")

    return redirect(url_for('resident_manage', resident_id=res_id))


@app.route('/cancel_distribute/<int:log_id>')
@login_required
def cancel_distribute(log_id):
    """물품 관리 페이지에서 지급 내역 취소(재고 복구)"""
    db.cancel_distribution(log_id); 
    
    broadcast_update()
    
    return redirect('/admin/supply')


@app.route('/cancel_resident_distribute/<int:log_id>')
@login_required
def cancel_resident_distribute(log_id):
    try:
        # [수정] DistributionLog.query.get(log_id) -> db.session.get 사용
        log = db.session.get(DistributionLog, log_id)
        
        if log:
            if log.supply:
                log.supply.quantity += log.quantity
                app.logger.info(f"↩️ 지급 취소(재고복구): {log.supply.item_name} +{log.quantity}")
            else:
                app.logger.warning(f"⚠️ 지급 취소(재고복구 실패): 연결된 물품 정보가 없습니다. (Log ID: {log_id})")
            
            db.session.delete(log)
            db.session.commit()
            
            broadcast_update()
            
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"❌ 지급 취소 중 오류 발생: {str(e)}")
        
    return redirect('/admin/resident')


@app.route('/cancel_resident_manage_distribute/<int:log_id>/<int:resident_id>')
@login_required
def cancel_resident_manage_distribute(log_id, resident_id):
    """이재민 상세 페이지에서 지급 내역 취소 및 재고 복구 (ORM 적용)"""
    try:
        # 1. 지급 로그 조회
        log = db.session.get(DistributionLog, log_id)
        
        if not log:
            flash("이미 삭제되었거나 존재하지 않는 기록입니다.", "warning")
            return redirect(url_for('resident_manage', resident_id=resident_id))

        # 2. 물품 재고 복구 (물품이 삭제되지 않았다면)
        supply = db.session.get(Supply, log.supply_id)
        if supply:
            supply.quantity += log.quantity
        else:
            # 물품 자체가 삭제된 경우라면 경고 로그만 남기고 기록은 삭제 진행
            app.logger.warning(f"지급 취소 중 물품(ID:{log.supply_id})을 찾을 수 없어 재고 복구 실패")

        # 3. 로그 삭제
        db.session.delete(log)
        db.session.commit()
        
        broadcast_update()
        
        flash("지급이 취소되고 물품 재고가 복구되었습니다.", "success")

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"지급 취소 중 오류: {e}")
        flash("취소 처리 중 시스템 오류가 발생했습니다.", "error")

    return redirect(url_for('resident_manage', resident_id=resident_id))



@app.route('/cancel_status_log/<int:log_id>/<int:resident_id>')
@login_required
def cancel_status_log(log_id, resident_id):
    """상태 변경 이력 삭제 (ORM 적용)"""
    try:
        # 1. 삭제할 로그 조회
        log_to_delete = db.session.get(ResidentLog, log_id)
        
        if not log_to_delete:
            flash("이미 삭제되었거나 존재하지 않는 기록입니다.", "warning")
            return redirect(url_for('resident_manage', resident_id=resident_id))

        # 2. 로그 삭제
        db.session.delete(log_to_delete)
        db.session.commit() # 로그만 지우면, 조회 시 자동으로 이전 로그가 최신이 됨

        # 3. 알림
        # 삭제 후 현재 상태 확인 (메시지용)
        last_log = ResidentLog.query.filter_by(resident_id=resident_id)\
                                    .order_by(ResidentLog.id.desc())\
                                    .first()
        current_status = last_log.status if last_log else "기록 없음"
        
        app.logger.info(f"상태 로그 삭제됨. 현재 표시 상태: {current_status}")
        flash(f"상태 변경 기록이 삭제되었습니다. (현재 상태: {current_status})", "success")

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"상태 로그 삭제 중 오류: {e}")
        flash("삭제 처리 중 시스템 오류가 발생했습니다.", "error")

    return redirect(url_for('resident_manage', resident_id=resident_id))
    

@app.route('/delete_supply/<int:sup_id>')
@login_required
def delete_supply(sup_id):
    """물품 삭제 (안전하게 수량만 0으로 초기화) - ORM 적용"""
    try:
        # [수정] Supply.query.get_or_404(sup_id) -> db.session.get 사용
        supply = db.session.get(Supply, sup_id)
        
        if not supply:
            flash("❌ 존재하지 않는 물품입니다.")
            return redirect('/admin/supply')
        
        supply.quantity = 0
        db.session.commit()
        
        broadcast_update()
        
        app.logger.info(f"🗑️ 물품 수량 초기화(삭제): {supply.item_name} (ID:{sup_id}) by {session.get('user_name')}")
        flash(f"✅ '{supply.item_name}'의 재고를 0으로 비웠습니다.")
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"❌ 물품 삭제(초기화) 오류: {str(e)}")
        flash("❌ 처리 중 오류가 발생했습니다.")
        
    return redirect('/admin/supply')
    
    
# ==========================================
# [7] 집결지 관리 (Assembly Point)
# ==========================================
@app.route('/admin/assembly')
@login_required
def admin_assembly():
    """집결지 목록 및 각 집결지에 배정된 목적 구호소 관리 (ORM 적용)"""
    
    # 1. 활성 집결지 조회
    assemblies_orm = AssemblyPoint.query.filter_by(is_active=True).all()
    
    # 2. 활성 구호소 조회 (드롭다운용)
    all_shelters = Shelter.query.filter_by(is_active=True).all()
    
    # 3. 데이터 구조 조립
    data = []
    for ap in assemblies_orm:
        # 해당 집결지에 연결된 목적 구호소 목록 추출
        # (models.py의 destinations 관계 활용)
        dests = []
        for d in ap.destinations:
            # d.target_shelter를 통해 구호소 정보 접근
            if d.target_shelter and d.target_shelter.is_active:
                dests.append({'id': d.target_shelter.id, 'name': d.target_shelter.name})
        
        # 템플릿 호환용 딕셔너리
        info = {
            'id': ap.id,
            'name': ap.name,
            'address': ap.address,
            'stop_no': ap.stop_no
        }
        data.append({'info': info, 'destinations': dests})

    # 템플릿용 구호소 리스트
    shelter_options = [{'id': s.id, 'name': s.name} for s in all_shelters]

    return render_template('admin_assembly.html', assemblies=data, all_shelters=shelter_options)


@app.route('/add_assembly', methods=['POST'])
@login_required
def add_assembly():
    """신규 집결지(Point) 등록 (ORM 적용)"""
    try:
        new_point = AssemblyPoint(
            name=request.form.get('name'),
            address=request.form.get('address'),
            stop_no=request.form.get('stop_no'),
            is_active=True
        )
        db.session.add(new_point)
        db.session.commit()
        
        broadcast_update()
        flash("✅ 신규 집결지가 등록되었습니다.")
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"❌ 집결지 등록 오류: {e}")
        flash("❌ 등록 중 오류가 발생했습니다.")
        
    return redirect('/admin/assembly')


@app.route('/delete_assembly/<int:a_id>')
@login_required
def delete_assembly(a_id):
    """집결지 삭제 (ORM 적용)"""
    try:
        # [수정] AssemblyPoint.query.get_or_404(a_id) -> db.session.get 사용
        point = db.session.get(AssemblyPoint, a_id)
        
        if point:
            db.session.delete(point)
            db.session.commit()
            
            broadcast_update()
            flash("🗑️ 집결지가 삭제되었습니다.")
        else:
             flash("❌ 존재하지 않는 집결지입니다.")
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"❌ 집결지 삭제 오류: {e}")
        flash("❌ 삭제 중 오류가 발생했습니다.")
        
    return redirect('/admin/assembly')


@app.route('/add_destination', methods=['POST'])
@login_required
def add_destination():
    """집결지에 배정될 목적 구호소 추가 (집결지 관리용)"""
    try:
        a_id = request.form.get('assembly_id')
        s_id = request.form.get('shelter_id')
        
        # 1. 기본 경유지 설정 (동화울교 -> 천변 -> 갑천대교)
        default_waypoints = "127.412678,36.385742|127.360745,36.359582"
        
        # 2. [조건] 집결지 ID가 '3'번(한국원자력연구원)인 경우만 경유지 없음(None)
        # form에서 넘어온 a_id는 문자열이므로 문자열 '3'과 비교해야 합니다.
        if str(a_id) == '3':
            final_waypoints = None
        else:
            final_waypoints = default_waypoints

        # 3. 중복 확인 후 저장
        exists = AssemblyDestination.query.filter_by(assembly_id=a_id, shelter_id=s_id).first()
        
        if not exists:
            new_dest = AssemblyDestination(
                assembly_id=a_id, 
                shelter_id=s_id, 
                waypoints=final_waypoints # 설정된 경유지 적용
            )
            db.session.add(new_dest)
            db.session.commit()
            
            broadcast_update()
            flash("✅ 목적지가 추가되었습니다.")
            
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"❌ 목적지 추가 오류: {e}")
        
    return redirect('/admin/assembly')


@app.route('/add_destination_direct', methods=['POST'])
@login_required
def add_destination_direct():
    """집결지-구호소 직접 연결 (구호소 관리용)"""
    # 로직은 위와 동일하며 리다이렉트 경로만 다름
    try:
        a_id = request.form.get('assembly_id')
        s_id = request.form.get('shelter_id')
        
        # 1. 기본 경유지 설정 (동화울교 -> 천변 -> 갑천대교)
        default_waypoints = "127.412678,36.385742|127.360745,36.359582"
        
        # 2. [조건] 집결지 ID가 '3'번(한국원자력연구원)인 경우만 경유지 없음(None)
        # form에서 넘어온 a_id는 문자열이므로 문자열 '3'과 비교해야 합니다.
        if str(a_id) == '3':
            final_waypoints = None
        else:
            final_waypoints = default_waypoints

        # 3. 중복 확인 후 저장
        exists = AssemblyDestination.query.filter_by(assembly_id=a_id, shelter_id=s_id).first()
        
        if not exists:
            new_dest = AssemblyDestination(
                assembly_id=a_id, 
                shelter_id=s_id, 
                waypoints=final_waypoints # 설정된 경유지 적용
            )
            db.session.add(new_dest)
            db.session.commit()
            
            broadcast_update()
            flash("✅ 목적지가 추가되었습니다.")
            
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"❌ 목적지 직접 추가 오류: {e}")

    return redirect('/admin/shelter')


@app.route('/delete_destination/<int:assembly_id>/<int:shelter_id>')
@login_required
def delete_destination(assembly_id, shelter_id):
    """집결지-구호소 연결 해제 (집결지 관리용)"""
    try:
        dest = AssemblyDestination.query.filter_by(assembly_id=assembly_id, shelter_id=shelter_id).first()
        if dest:
            db.session.delete(dest)
            db.session.commit()
            
            broadcast_update()
            
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"❌ 목적지 해제 오류: {e}")
        
    return redirect('/admin/assembly')


@app.route('/delete_destination_from_shelter/<int:s_id>/<int:a_id>')
@login_required
def delete_dest_from_shelter(s_id, a_id):
    """집결지-구호소 연결 해제 (구호소 관리용)"""
    try:
        dest = AssemblyDestination.query.filter_by(assembly_id=a_id, shelter_id=s_id).first()
        if dest:
            db.session.delete(dest)
            db.session.commit()
            
            broadcast_update()
            
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"❌ 목적지 해제(구호소측) 오류: {e}")
        
    return redirect('/admin/shelter')


# ==========================================
# [8] 시스템 관리 (DB Explorer, Logs)
# ==========================================
@app.route('/db_explorer', methods=['GET', 'POST'])
#@login_required
def db_explorer():
    #if session.get('role') != 1: 
        #return "권한이 없습니다.", 403
    
    # [수정] SQLAlchemy 2.0 호환성 처리 (inspect 사용)
    try:
        inspector = inspect(db.engine)
        tables = inspector.get_table_names()
    except Exception as e:
        app.logger.error(f"테이블 목록 조회 실패: {e}")
        tables = []

    selected_table = request.args.get('table')
    query = request.form.get('query', '')
    columns = []
    rows = []
    error = None

    try:
        # A. 쿼리 직접 실행 (POST)
        if request.method == 'POST' and query:
            # SQL 실행 (text()로 감싸야 함)
            result = db.session.execute(text(query))
            
            if result.returns_rows:
                columns = result.keys() # 컬럼명
                rows = result.fetchall() # 데이터
            else:
                db.session.commit() # INSERT/UPDATE/DELETE 확정
                error = f"실행 완료 (행 영향: {result.rowcount}개)"
        
        # B. 테이블 선택 조회 (GET)
        elif selected_table:
            # 테이블 데이터 조회
            result = db.session.execute(text(f"SELECT * FROM {selected_table} LIMIT 100"))
            columns = result.keys()
            rows = result.fetchall()
            
    except Exception as e:
        db.session.rollback()
        error = f"SQL 오류: {str(e)}"
        
    return render_template('db_explorer.html', tables=tables, selected_table=selected_table,
                           columns=columns, rows=rows, query=query, error=error)


@app.route('/admin/db_control/<action>')
#@login_required
def admin_db_control(action):
    # 관리자 권한 체크
    #if session.get('role') != 1:
        #return "권한이 없습니다.", 403

    try:
        # ----------------------------------------------------
        # 1. 모든 데이터 삭제 (공통)
        # ----------------------------------------------------
        
        # SQLite 외래키(Foreign Key) 제약 일시 해제
        db.session.execute(text("PRAGMA foreign_keys = OFF"))
        
        # ORM 메타데이터에 등록된 모든 테이블의 데이터 삭제
        for table in db.metadata.tables.values():
            db.session.execute(table.delete())
            
            # (선택사항) Auto Increment(ID) 카운터 초기화
            try:
                db.session.execute(text(f"DELETE FROM sqlite_sequence WHERE name='{table.name}'"))
            except Exception:
                pass # sqlite_sequence 테이블이 없거나 실패 시 무시

        db.session.execute(text("PRAGMA foreign_keys = ON"))
        
        msg = "🗑️ 모든 데이터가 삭제되었습니다."

        # ----------------------------------------------------
        # 2. 초기화(Init) 요청인 경우 기초 데이터 삽입
        # ----------------------------------------------------
        if action == 'init':
            
            # [A] 실제 구호소 데이터 삽입
            shelter_list = [
                Shelter(name='유성종합스포츠센터', address='대전광역시 유성구 유성대로 978', phone='', area=4986, capacity=1385, latitude=36.379005, longitude=127.343324),
                Shelter(name='지족초등학교', address='대전광역시 유성구 노은서로 238', phone='042-824-3144', area=12100, capacity=3661, latitude=36.380684, longitude=127.317369),
                Shelter(name='지족중학교', address='대전광역시 유성구 노은동로 193', phone='042-477-4640', area=13791, capacity=4172, latitude=36.378244, longitude=127.320588),
                Shelter(name='지족고등학교', address='대전광역시 유성구 노은서로 202', phone='042-476-2706', area=12778, capacity=3866, latitude=36.378134, longitude=127.315549),
                Shelter(name='노은초등학교', address='대전광역시 유성구 노은동로99번길 35', phone='042-476-1492', area=13120, capacity=3969, latitude=36.368924, longitude=127.321425),
                Shelter(name='노은중학교', address='대전광역시 유성구 노은동로 104', phone='042-479-5554', area=13033, capacity=3943, latitude=36.370082, longitude=127.324187),
                Shelter(name='노은고등학교', address='대전광역시 유성구 노은동로99번길 55', phone='042-717-3600', area=11438, capacity=3460, latitude=36.369013, longitude=127.319228),
                Shelter(name='유성중학교', address='대전광역시 유성구 상대로 33', phone='042-822-1605', area=13833, capacity=4185, latitude=36.345903, longitude=127.334768),
                Shelter(name='봉명초등학교', address='대전광역시 유성구 계룡로132번길 62', phone='042-820-8800', area=13549, capacity=4099, latitude=36.349582, longitude=127.343527),
                Shelter(name='봉명중학교', address='대전광역시 유성구 계룡로132번길 71', phone='042-826-6872', area=12764, capacity=3862, latitude=36.349713, longitude=127.344561),
                Shelter(name='상대초등학교', address='대전광역시 유성구 월드컵대로 321', phone='042-826-1720', area=10202, capacity=3087, latitude=36.347635, longitude=127.336504),
                Shelter(name='원신흥초등학교', address='대전광역시 유성구 원신흥로55번길 37', phone='042-826-9811', area=9231, capacity=2793, latitude=36.340858, longitude=127.342506),
                Shelter(name='흥도초등학교', address='대전광역시 유성구 도안동로 323', phone='042-822-5083', area=11069, capacity=3349, latitude=36.334103, longitude=127.338713)
            ]
            db.session.add_all(shelter_list)
            
            # [B] 실제 집결지 데이터 삽입 (좌표 추가됨)
            assembly_list = [
                AssemblyPoint(name='관평동주민센터', stop_no='', address='대전광역시 유성구 관평2로 42', latitude=36.423096, longitude=127.388922),
                AssemblyPoint(name='구즉동주민센터', stop_no='82520', address='대전광역시 유성구 구룡달전로 22', latitude=36.440336, longitude=127.383784),
                AssemblyPoint(name='한국원자력연구원', stop_no='', address='대전광역시 유성구 덕진동 453', latitude=36.420748, longitude=127.375128),
                AssemblyPoint(name='관평중학교', stop_no='', address='대전광역시 유성구 관평동 901', latitude=36.424873, longitude=127.388094),
                AssemblyPoint(name='관평초등학교', stop_no='', address='대전광역시 유성구 관평동 900', latitude=36.423731, longitude=127.387190),
                AssemblyPoint(name='배울초등학교', stop_no='', address='대전광역시 유성구 배울2로 8', latitude=36.422048, longitude=127.384434),
                AssemblyPoint(name='롯데마트대덕점', stop_no='44590', address='대전광역시 유성구 테크노중앙로 36', latitude=36.426896, longitude=127.389686),
                AssemblyPoint(name='수변공원', stop_no='44670', address='대전광역시 유성구 테크노중앙로 68', latitude=36.425588, longitude=127.392873),
                AssemblyPoint(name='테크노밸리6단지', stop_no='47100', address='대전광역시 유성구 관평동 683', latitude=36.418499, longitude=127.387979),
                AssemblyPoint(name='두리초등학교', stop_no='', address='대전광역시 유성구 와룡로 37', latitude=36.429395, longitude=127.382383),
                AssemblyPoint(name='두리중학교', stop_no='', address='대전광역시 유성구 와룡로37번길 20', latitude=36.429054, longitude=127.381100),
                AssemblyPoint(name='한솔아파트', stop_no='44750', address='대전광역시 유성구 구즉로 25', latitude=36.432691, longitude=127.384381),
                AssemblyPoint(name='북부여성가족원', stop_no='44840', address='대전광역시 유성구 대덕대로 1173', latitude=36.431323, longitude=127.387177),
                AssemblyPoint(name='송강전통시장입구', stop_no='44830', address='대전광역시 유성구 봉산로 17', latitude=36.435290, longitude=127.387256),
                AssemblyPoint(name='휴먼시아아파트', stop_no='44770', address='대전광역시 유성구 와룡로136번길 75', latitude=36.437984, longitude=127.385128),
                AssemblyPoint(name='송강중학교', stop_no='', address='대전광역시 유성구 와룡로 122', latitude=36.437677, longitude=127.381738),
                AssemblyPoint(name='송강초등학교', stop_no='', address='대전광역시 유성구 송강로42번길 6', latitude=36.434487, longitude=127.384016)
            ]
            db.session.add_all(assembly_list)
            
            # [C] 계정 생성
            # Role Level -> 1:최고관리자(zips), 2:모니터/일반관리자, 3:현장근무자
            users = [
                User(login_id='zips', password=generate_password_hash('zips7870!'), role_level=1),
                User(login_id='admin', password=generate_password_hash('dnjswkfur'), role_level=2),
                User(login_id='monitor', password=generate_password_hash('dnjswkfur'), role_level=2),
                User(login_id='staff', password=generate_password_hash('dnjswkfur'), role_level=3)
            ]
            db.session.add_all(users)
            
            # [D] 샘플 물품 데이터
            supplies = [
                Supply(id=1, item_name='구호세트(남/대)', quantity=12, shelter_id=None),
                Supply(id=2, item_name='구호세트(남/중)', quantity=22, shelter_id=None),
                Supply(id=3, item_name='구호세트(남/소)', quantity=8, shelter_id=None),
                Supply(id=4, item_name='구호세트(여/대)', quantity=12, shelter_id=None),
                Supply(id=5, item_name='구호세트(여/중)', quantity=23, shelter_id=None),
                Supply(id=6, item_name='구호세트(여/소)', quantity=8, shelter_id=None),
                Supply(id=7, item_name='취사세트', quantity=34, shelter_id=None)
            ]
            db.session.add_all(supplies)
            
            # [E] 집결지-구호소 연결 및 경로 데이터 생성
            # 데이터 형식: (집결지ID, 구호소ID, 경유지String)
            # dest_data = [
                # (3, 1, None), # 3번 집결지 -> 1번 구호소 (경유지 없음)
                # (7, 13, "127.412678,36.385742|127.358526,36.359139"),
                # (8, 13, "127.412678,36.385742|127.358526,36.359139"),
                # (4, 10, "127.412678,36.385742|127.358526,36.359139"),
                # (5, 9, "127.412678,36.385742|127.358526,36.359139"),
                # (6, 8, "127.412678,36.385742|127.358526,36.359139"),
                # (1, 11, "127.412678,36.385742|127.358526,36.359139"),
                # (9, 12, "127.412678,36.385742|127.358526,36.359139"),
                # (3, 13, "127.412678,36.385742|127.358526,36.359139"), # 3번 집결지는 13번 구호소로도 연결됨
                # (10, 2, "127.412678,36.385742|127.358526,36.359139"),
                # (11, 2, "127.412678,36.385742|127.358526,36.359139"),
                # (10, 1, "127.412678,36.385742|127.358526,36.359139"),
                # (11, 1, "127.412678,36.385742|127.358526,36.359139"),
                # (12, 3, "127.412678,36.385742|127.358526,36.359139"),
                # (13, 4, "127.412678,36.385742|127.358526,36.359139"),
                # (14, 4, "127.412678,36.385742|127.358526,36.359139"),
                # (2, 5, "127.412678,36.385742|127.358526,36.359139"),
                # (16, 6, "127.412678,36.385742|127.358526,36.359139"),
                # (17, 7, "127.412678,36.385742|127.358526,36.359139"),
                # (15, 5, "127.412678,36.385742|127.358526,36.359139")
            # ]

            # destinations = []
            # for item in dest_data:
                # destinations.append(
                    # AssemblyDestination(
                        # assembly_id=item[0],
                        # shelter_id=item[1],
                        # waypoints=item[2]
                    # )
                # )
            
            # db.session.add_all(destinations)
            
            msg = "🔄 데이터가 초기화되었습니다."

        # 최종 커밋 (모든 INSERT 반영)
        db.session.commit()
        
        app.logger.warning(f"⚠️ DB Action '{action}' executed by {session.get('user_name')}")
        flash(f"✅ {msg}")

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"❌ DB Control Error: {str(e)}")
        flash(f"❌ 오류 발생: {str(e)}")

    return redirect('/db_explorer')


@app.route('/logs')
@login_required
def view_logs():
    if session.get('role') != 1: return "권한 없음", 403
    logs = []
    if os.path.exists(log_filename):
        with open(log_filename, 'r', encoding='utf-8') as f:
            logs = f.readlines()[::-1][:200]
    return render_template('logs.html', logs=logs)


@app.route('/upload')
@login_required
def upload():
    """서버 파일 브라우저 및 업로드 관리 페이지"""
    base_dir = os.path.dirname(os.path.abspath(__file__))
    selected_folder = request.args.get('folder', '') 
    folder_list, file_list = [], []
    exclude = {'.git', '__pycache__', '.venv', '.idea', '.vscode', 'uploads'}
    for root, dirs, files in os.walk(base_dir):
        dirs[:] = [d for d in dirs if d not in exclude]
        rel_path = os.path.relpath(root, base_dir).replace("\\", "/")
        path_val = "" if rel_path == "." else rel_path
        folder_list.append({"display": rel_path, "value": path_val})
        if path_val == selected_folder: file_list = files
    return render_template('upload_files.html', folders=sorted(folder_list, key=lambda x:x['display']), files=file_list, current_folder=selected_folder)

@app.route('/upload_files', methods=['POST'])
@login_required
def upload_files():
    """서버 특정 폴더로 파일 다중 업로드"""
    user_path = request.form.get('upload_folder_direct') or request.form.get('upload_folder_select', '')
    base_dir = os.path.dirname(os.path.abspath(__file__))
    target_dir = os.path.normpath(os.path.join(base_dir, user_path.strip()))
    if not target_dir.startswith(base_dir): target_dir = base_dir
    if not os.path.exists(target_dir): os.makedirs(target_dir)
    files = request.files.getlist('files')
    for f in files:
        if f.filename: f.save(os.path.join(target_dir, os.path.basename(f.filename)))
    flash(f"✅ 파일 업로드 완료: {user_path}")
    return redirect(url_for('upload'))


@app.route('/download/<path:folder_path>/<filename>')
@login_required
def download_file(folder_path, filename):
    """서버 파일 개별 다운로드"""
    base_dir = os.path.dirname(os.path.abspath(__file__))
    target_dir = base_dir if folder_path == 'root' else os.path.join(base_dir, folder_path)
    return send_from_directory(target_dir, filename, as_attachment=True)


@app.route('/delete_file/<path:folder_path>/<filename>')
@login_required
def delete_file(folder_path, filename):
    """서버 파일 개별 삭제"""
    base_dir = os.path.dirname(os.path.abspath(__file__))
    target_dir = base_dir if folder_path == 'root' else os.path.join(base_dir, folder_path)
    file_path = os.path.join(target_dir, filename)
    if os.path.exists(file_path): os.remove(file_path); flash(f"✅ {filename} 삭제됨")
    return redirect(url_for('upload', folder=folder_path if folder_path != 'root' else ''))


@app.route('/download_project')
@login_required
def download_project():
    """프로젝트 전체 소스코드 압축 백업(ZIP) 생성"""
    base_dir = os.path.dirname(os.path.abspath(__file__))
    backup_dir = os.path.join(base_dir, '_backup')
    if not os.path.exists(backup_dir): os.makedirs(backup_dir)
    zip_target = os.path.join(backup_dir, f"backup_{datetime.now().strftime('%Y%m%d_%H%M')}")
    try:
        shutil.make_archive(base_name=zip_target, format='zip', root_dir=base_dir)
        flash("✅ 프로젝트 백업 완료")
    except Exception as e: flash(f"❌ 오류: {str(e)}")
    return redirect(url_for('upload'))

# ==========================================
# [9] 기타 (카카오 로그인 등)
# ==========================================

@app.route('/kakao/resident_login/<int:shelter_id>')
def kakao_resident_login(shelter_id):
    """
    이재민이 QR을 찍고 '카카오로 등록하기'를 눌렀을 때 진입.
    shelter_id를 state 파라미터에 담아서 카카오 인증 서버로 보냄.
    """
    kakao_auth_url = (
        f"https://kauth.kakao.com/oauth/authorize?"
        f"client_id={KAKAO_REST_API_KEY}&"
        f"redirect_uri={KAKAO_REDIRECT_URI}&"  # 관리자와 같은 Redirect URI 사용 (분기 처리 필요)
        f"response_type=code&"
        f"scope=talk_message,profile_nickname&" # 메시지, 닉네임 권한 요청
        f"state=resident_{shelter_id}" # [중요] 구호소 ID를 state에 저장 (형식: resident_1)
    )
    return redirect(kakao_auth_url)


# 기존 kakao_callback 함수를 수정하여 관리자/이재민 로그인을 분기 처리합니다.
@app.route('/oauth/kakao/callback')
def kakao_callback():
    code = request.args.get('code')
    state = request.args.get('state', '') # state 값 확인
    
    # 1. 토큰 발급
    token_url = "https://kauth.kakao.com/oauth/token"
    data = {
        "grant_type": "authorization_code",
        "client_id": KAKAO_REST_API_KEY,
        "redirect_uri": KAKAO_REDIRECT_URI,
        "code": code
    }
    response = requests.post(token_url, data=data)
    tokens = response.json()
    access_token = tokens.get("access_token")

    if not access_token:
        return f"카카오 인증 실패: {tokens}"

    # 2. 사용자 정보 가져오기 (이름, 카카오ID)
    user_url = "https://kapi.kakao.com/v2/user/me"
    headers = {"Authorization": f"Bearer {access_token}"}
    user_res = requests.post(user_url, headers=headers)
    user_info = user_res.json()
    
    kakao_id = str(user_info.get('id'))
    nickname = user_info.get('properties', {}).get('nickname', '이름없음')

    # ----------------------------------------------------
    # [분기 1] 이재민 입소 등록 (state가 'resident_'로 시작하는 경우)
    # ----------------------------------------------------
    if state.startswith('resident_'):
        try:
            shelter_id = int(state.split('_')[1]) # 구호소 ID 추출
            
            conn = db.get_connection()
            cursor = conn.cursor()
            
            # 구호소 이름 가져오기 (메시지용)
            cursor.execute('SELECT name FROM shelters WHERE id = ?', (shelter_id,))
            sh_row = cursor.fetchone()
            shelter_name = sh_row[0] if sh_row else "지정 구호소"

            # 3. 이미 등록된 카카오 사용자인지 확인
            cursor.execute('SELECT id, name FROM residents WHERE kakao_id = ?', (kakao_id,))
            exist_user = cursor.fetchone()
            
            res_id = None
            
            if exist_user:
                # 이미 등록된 주민 -> 입소 처리만 수행
                res_id = exist_user[0]
                nickname = exist_user[1] # 기존 이름 사용
                # 입소 로그 추가
                cursor.execute('INSERT INTO resident_logs (resident_id, shelter_id, status, log_time) VALUES (?, ?, "IN", ?)',
                               (res_id, shelter_id, datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
            else:
                # 신규 등록 -> 주민 테이블 Insert + 입소 처리
                family_id = f"FAM-{datetime.now().strftime('%m%d%H%M%S')}"
                cursor.execute('''INSERT INTO residents (name, kakao_id, village, family_id, family_role) 
                                  VALUES (?, ?, ?, ?, ?)''', (nickname, kakao_id, '카카오연동', family_id, '세대주'))
                res_id = cursor.lastrowid
                cursor.execute('INSERT INTO resident_logs (resident_id, shelter_id, status, log_time) VALUES (?, ?, "IN", ?)',
                               (res_id, shelter_id, datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
            
            conn.commit()
            conn.close()

            # 4. [알림] 이재민 본인에게 입소 확인 카톡 전송
            send_kakao_self_message(access_token, nickname, shelter_name)

            # 5. [시스템 알림] 상황실에 알림
            socketio.emit('sys_notification', {
                'message': f"🔔 [카카오] {nickname}님이 {shelter_name}에 입소 등록하였습니다.",
                'shelter_id': shelter_id,
                'resident_id': res_id,
                'time': datetime.now().strftime('%H:%M:%S')
            }, namespace='/')

            flash(f"✅ {nickname}님, {shelter_name} 입소 처리가 완료되었습니다.")
            return redirect(url_for('user_info', resident_id=res_id))

        except Exception as e:
            app.logger.error(f"Kakao Resident Login Error: {e}")
            return f"오류 발생: {str(e)}"

    # ----------------------------------------------------
    # [분기 2] 관리자 로그인 (기존 로직)
    # ----------------------------------------------------
    else:
        session['kakao_token'] = access_token
        flash("✅ 관리자 카카오 연동 완료")
        return redirect('/')


def send_kakao_self_message(token, user_name, shelter_name):
    """이재민에게 입소 완료 메시지 전송 (나에게 보내기 API 활용)"""
    url = "https://kapi.kakao.com/v2/api/talk/memo/default/send"
    headers = {"Authorization": f"Bearer {token}"}
    
    text_msg = (
        f"[Shelter-On 입소 알림]\n\n"
        f"반갑습니다, {user_name}님.\n"
        f"'{shelter_name}'에 안전하게 등록되었습니다.\n\n"
        f"📅 시간: {datetime.now().strftime('%Y-%m-%d %H:%M')}\n"
        f"🆘 필요 물품이 있으면 상황실에 요청해주세요."
    )
    
    payload = {
        "object_type": "text",
        "text": text_msg,
        "link": {
            "web_url": "http://localhost:7870", # 실제 도메인이 있다면 변경
            "mobile_web_url": "http://localhost:7870"
        },
        "button_title": "내 입소정보 확인"
    }
    
    data = {"template_object": json.dumps(payload)}
    requests.post(url, headers=headers, data=data)

# ==========================================
# [10] 에러 핸들링 
# ==========================================
@app.errorhandler(404)
def page_not_found(e):
    # [노이즈 필터링] Chrome DevTools 요청은 로그 남기지 않고 조용히 무시
    if 'com.chrome.devtools.json' in request.path:
        return "", 404

    # 진짜 404 에러만 로그에 기록
    app.logger.warning(f"404 Error: {request.url}")
    return render_template('errors/404.html'), 404


@app.errorhandler(500)
def internal_server_error(e):
    app.logger.error(f"500 Error: {e}")
    # DB 트랜잭션 중 에러가 났을 수 있으므로 롤백 수행
    db.session.rollback()
    return render_template('errors/500.html', error=str(e)), 500


@app.errorhandler(Exception)
def handle_exception(e):
    """예상치 못한 모든 에러를 잡아서 친절하게 표시"""
    app.logger.error(f"Unhandled Exception[오류]: {e}")
    return render_template('errors/500.html', error="일시적인 오류가 발생했습니다. 잠시 후 다시 시도해주세요."), 500
    
# ==========================================
# [11] 실행 설정
# ==========================================

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    socketio.run(app, host='0.0.0.0', port=7870, debug=True, allow_unsafe_werkzeug=True)
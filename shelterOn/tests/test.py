import os
import pytest
from sqlalchemy import desc

# =============================================================================
# [1] 앱 임포트 전 환경변수 설정
# =============================================================================
base_dir = os.path.dirname(os.path.abspath(__file__))
test_db_path = os.path.join(base_dir, 'test_db.sqlite').replace('\\', '/')
test_uri = f"sqlite:///{test_db_path}"

os.environ['DATABASE_URL'] = test_uri 

from app import app
from models import db, User, Shelter, Resident, ResidentLog, Supply, AssemblyPoint, AssemblyDestination, DistributionLog, DutyOrder, StaffLog

# ==========================================
# [2] 테스트 환경 설정 (Fixtures)
# ==========================================

@pytest.fixture(scope='module')
def client():
    print("\n\n[System] 🧪 테스트 환경 초기화 시작...")
    
    app.config.update({
        'TESTING': True,
        'SQLALCHEMY_DATABASE_URI': test_uri,
        'SECRET_KEY': 'test_secret',
        'SQLALCHEMY_TRACK_MODIFICATIONS': False
    })
    
    with app.app_context():
        db.session.remove()
        db.engine.dispose()
        app._got_first_request = False 
        
        if 'sqlalchemy' in app.extensions:
            app.extensions.pop('sqlalchemy')
            
        db.init_app(app)
        
        try:
            current_db = str(db.engine.url)
            if 'shelter.db' in current_db and 'test' not in current_db:
                raise RuntimeError(f"⚠️ 위험! 운영 DB 연결 감지: {current_db}")
        except Exception:
            pass

        db.drop_all()   
        db.create_all() 
        
        if not User.query.filter_by(login_id='admin').first():
            admin = User(login_id='admin', password='dev_password', role_level=1)
            db.session.add(admin)
            db.session.commit()

    with app.test_client() as client:
        yield client

    with app.app_context():
        db.session.remove()
        db.drop_all()


@pytest.fixture(autouse=True)
def clean_db(client):
    with app.app_context():
        for table in reversed(db.metadata.sorted_tables):
            db.session.execute(table.delete())
        
        admin = User(login_id='admin', password='dev_password', role_level=1)
        db.session.add(admin)
        db.session.commit()
    yield


@pytest.fixture
def admin_session(client):
    with client.session_transaction() as sess:
        sess['logged_in'] = True
        sess['role'] = 1
        sess['user_name'] = '테스트관리자'
    return client

# ==========================================
# [3] 테스트 케이스 (시나리오)
# ==========================================

def test_shelter_lifecycle(admin_session):
    print("\n🔹 [Case 1] 구호소 추가 및 상태 변경 테스트")
    
    admin_session.post('/add_shelter', data={
        'name': '제1대피소', 'address': '서울', 'phone': '010-0000-0000',
        'area': 100, 'capacity': 50
    }, follow_redirects=True)

    with app.app_context():
        shelter = Shelter.query.filter_by(name='제1대피소').first()
        s_id = shelter.id
        assert shelter.is_active == True

    admin_session.get(f'/toggle_shelter/{s_id}/1', follow_redirects=True)

    with app.app_context():
        shelter = db.session.get(Shelter, s_id)
        assert shelter.is_active == False
        print("   ✅ 구호소 상태 변경 확인됨")

def test_assembly_workflow(admin_session):
    print("\n🔹 [Case 2] 집결지 추가 및 구호소 연결 테스트")
    
    with app.app_context():
        s = Shelter(name='연결용구호소', is_active=True)
        db.session.add(s)
        db.session.commit()
        s_id = s.id

    admin_session.post('/add_assembly', data={
        'name': '시청앞광장', 'address': '서울시청', 'stop_no': '12345'
    }, follow_redirects=True)

    with app.app_context():
        ap = AssemblyPoint.query.filter_by(name='시청앞광장').first()
        a_id = ap.id
        assert ap is not None

    admin_session.post('/add_destination', data={
        'assembly_id': a_id, 'shelter_id': s_id
    }, follow_redirects=True)

    with app.app_context():
        link = AssemblyDestination.query.filter_by(assembly_id=a_id, shelter_id=s_id).first()
        assert link is not None
        print("   ✅ 집결지-구호소 연결 확인됨")

def test_resident_full_process(admin_session):
    print("\n🔹 [Case 3] 주민 입소 -> 상태변경 -> 퇴소 테스트")
    
    with app.app_context():
        s = Shelter(name='주민구호소', is_active=True)
        db.session.add(s)
        db.session.commit()
        sh_id = s.id

    admin_session.post('/add_resident_admin', data={
        'name': '홍길동', 'phone': '010-1111-2222', 'gender': '남', 'age': '30',
        'shelter_id': sh_id, 'family_role': '세대주'
    }, follow_redirects=True)

    with app.app_context():
        res = Resident.query.filter_by(name='홍길동').first()
        res_id = res.id
        log = ResidentLog.query.filter_by(resident_id=res_id).first()
        assert log.status == 'IN'

    admin_session.get(f'/update_status/list/{res_id}/{sh_id}/HOSPITAL', follow_redirects=True)

    with app.app_context():
        last_log = ResidentLog.query.filter_by(resident_id=res_id).order_by(ResidentLog.id.desc()).first()
        assert last_log.status == 'HOSPITAL'
        print("   ✅ 주민 상태 변경(병원) 확인됨")
        
       
        
def test_status_log_rollback(admin_session):
    print("\n🔹 [Case 4] 상태 변경 및 취소 시 롤백 테스트")
    
    with app.app_context():
        s = Shelter(name='상태구호소', is_active=True)
        db.session.add(s)
        db.session.flush()
        
        res = Resident(name='이영희', family_id='FAM002')
        db.session.add(res)
        db.session.flush()
        
        # [수정] Resident 객체에 status 설정 금지. Log만 추가.
        log1 = ResidentLog(resident_id=res.id, shelter_id=s.id, status='IN')
        db.session.add(log1)
        db.session.commit()
        
        res_id = res.id
        sh_id = s.id

    # 상태 변경 (IN -> HOSPITAL)
    admin_session.get(f'/update_status/manage/{res_id}/{sh_id}/HOSPITAL', follow_redirects=True)

    with app.app_context():
        # 최신 로그가 HOSPITAL인지 확인
        last_log = ResidentLog.query.filter_by(resident_id=res_id).order_by(ResidentLog.id.desc()).first()
        assert last_log.status == 'HOSPITAL'
        log_id_to_cancel = last_log.id

    # 변경 취소 (cancel_status_log)
    admin_session.get(f'/cancel_status_log/{log_id_to_cancel}/{res_id}', follow_redirects=True)

    with app.app_context():
        # 취소 후 최신 로그가 다시 IN인지 확인
        current_last_log = ResidentLog.query.filter_by(resident_id=res_id).order_by(ResidentLog.id.desc()).first()
        assert current_last_log.status == 'IN'


def test_supply_distribution_flow(admin_session):
    print("\n🔹 [Case 5] 물품 분배 및 취소(재고 복구) 테스트")
    
    with app.app_context():
        s = Shelter(name='물품구호소', is_active=True)
        db.session.add(s)
        db.session.flush()
        
        # [수정] Resident 생성 시 shelter_id 제거 (Logs로 연결)
        res = Resident(name='김철수', family_id='FAM001')
        db.session.add(res)
        db.session.flush()
        
        # 입소 로그 추가 (구호소 연결)
        db.session.add(ResidentLog(resident_id=res.id, shelter_id=s.id, status='IN'))
        
        sup = Supply(item_name='라면', quantity=10, shelter_id=s.id)
        db.session.add(sup)
        db.session.commit()
        
        res_id = res.id
        sup_id = sup.id

    # 물품 지급 (3개)
    admin_session.post('/manage_distribute', data={
        'res_id': res_id, 'sup_id': sup_id, 'quantity': 3
    }, follow_redirects=True)
    
    with app.app_context():
        updated_sup = db.session.get(Supply, sup_id)
        log = DistributionLog.query.filter_by(resident_id=res_id).first()
        
        assert updated_sup.quantity == 7 
        assert log is not None
        log_id = log.id

    # 지급 취소
    admin_session.get(f'/cancel_resident_manage_distribute/{log_id}/{res_id}', follow_redirects=True)
    print("   ✅ 물품 분배 및 취소 확인됨")

    with app.app_context():
        restored_sup = db.session.get(Supply, sup_id)
        deleted_log = db.session.get(DistributionLog, log_id)
        
        assert restored_sup.quantity == 10
        assert deleted_log is None


def test_staff_duty_cycle(client, admin_session):
    print("\n🔹 [Case 6] 근무자 명령 등록 -> 근무 시작 -> 종료 테스트")
    
    with app.app_context():
        s = Shelter(name='근무지구호소', is_active=True)
        db.session.add(s)
        db.session.commit()
        sh_id = s.id

    admin_session.post('/add_duty_order', data={
        'name': '김근무', 'dept': '안전과', 'phone': '010-9999-9999',
        'mission': '입구통제', 'shelter_id': sh_id
    }, follow_redirects=True)

    with app.app_context():
        order = DutyOrder.query.filter_by(name='김근무').first()
        duty_id = order.id

    # 근무 시작
    with client.session_transaction() as sess:
        sess['temp_staff_login'] = True
    
    client.post('/start_work', data={'duty_id': duty_id}, follow_redirects=True)

    with app.app_context():
        updated_order = db.session.get(DutyOrder, duty_id)
        staff_log = StaffLog.query.filter_by(user_name='김근무', logout_time=None).first()
        assert updated_order.is_working == True
        assert staff_log is not None
        print("   ✅ 근무 시작 및 로그 생성 확인됨")

    # 근무 종료
    client.get('/finish_work', follow_redirects=True)

    with app.app_context():
        finished_log = StaffLog.query.filter_by(user_name='김근무').order_by(StaffLog.id.desc()).first()
        assert finished_log.logout_time is not None
        print("   ✅ 근무 종료 처리 확인됨")


def test_user_register_public_access(client):
    print("\n🔹 [Case 7] 입소 등록 페이지(QR) 공개 접근 테스트")
    
    with app.app_context():
        s = Shelter(name='오픈구호소', is_active=True)
        db.session.add(s)
        db.session.commit()
        sid = s.id

    response = client.get(f'/register/{sid}')
    assert response.status_code == 200
    
    response_404 = client.get('/register/999999')
    assert response_404.status_code == 404
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

# DB 객체 생성 (app.py에서 init_app으로 연결)
db = SQLAlchemy()

# ==========================================
# 0. 사고 정보 관리 (새로 추가된 최상위 모델)
# ==========================================
class Incident(db.Model):
    """발생한 사고/재난 정보"""
    __tablename__ = 'incidents'

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)    # 사고명
    incident_type = db.Column(db.String(50))            # 유형 (수해, 지진 등)
    incident_category = db.Column(db.String(50))        # [추가] 실제사고 / 훈련 구분
    incident_time = db.Column(db.String(50))            # 사고 발생 시간
    status = db.Column(db.String(20), default='ACTIVE') # ACTIVE, CLOSED
    created_at = db.Column(db.DateTime, default=datetime.now)
    description = db.Column(db.Text)

    # 관계 설정 유지
    shelters = db.relationship('Shelter', backref='incident', lazy=True)
    assembly_points = db.relationship('AssemblyPoint', backref='incident', lazy=True)
    residents = db.relationship('Resident', backref='incident', lazy=True)

    def __repr__(self):
        return f'<Incident {self.title}>'

# ==========================================
# 6. 템플릿 관리 (사고 유형별 기본 설정)
# ==========================================
class TemplateShelter(db.Model):
    """사고 유형별 기본 구호소 템플릿"""
    __tablename__ = 'template_shelters'
    id = db.Column(db.Integer, primary_key=True)
    incident_type = db.Column(db.String(50), nullable=False) # 화재, 지진 등
    name = db.Column(db.String(100), nullable=False)
    address = db.Column(db.String(200))
    phone = db.Column(db.String(20))
    area = db.Column(db.Integer)
    capacity = db.Column(db.Integer)
    latitude = db.Column(db.Float)
    longitude = db.Column(db.Float)

class TemplateAssembly(db.Model):
    """사고 유형별 기본 집결지 템플릿"""
    __tablename__ = 'template_assemblies'
    id = db.Column(db.Integer, primary_key=True)
    incident_type = db.Column(db.String(50), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    address = db.Column(db.String(200))
    stop_no = db.Column(db.String(50))
    latitude = db.Column(db.Float)
    longitude = db.Column(db.Float)

class TemplateRoute(db.Model):
    """사고 유형별 기본 대피 경로 템플릿"""
    __tablename__ = 'template_routes'
    id = db.Column(db.Integer, primary_key=True)
    incident_type = db.Column(db.String(50), nullable=False)
    # 템플릿 ID를 참조하여 연결
    assembly_tmp_id = db.Column(db.Integer, db.ForeignKey('template_assemblies.id'))
    shelter_tmp_id = db.Column(db.Integer, db.ForeignKey('template_shelters.id'))
    waypoints = db.Column(db.Text)

# ==========================================
# 1. 사용자 및 인증 관리 (기존 유지)
# ==========================================
class User(db.Model):
    """관리자, 모니터링 요원 등 시스템 사용자"""
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    login_id = db.Column(db.String(50), unique=True, nullable=False) # 로그인 ID
    password = db.Column(db.String(200), nullable=False) # 해시된 비밀번호
    role_level = db.Column(db.Integer, default=3) 
    # 1: 본부(Admin), 2: 모니터(View), 3: 현장(Staff)

    def __repr__(self):
        return f'<User {self.login_id}>'


# ==========================================
# 2. 시설 관리 (Shelter, AssemblyPoint에 incident_id 추가)
# ==========================================
class Shelter(db.Model):
    """이재민 대피소 (구호소)"""
    __tablename__ = 'shelters'

    id = db.Column(db.Integer, primary_key=True)
    # [추가] 어떤 사고에 배정된 구호소인지 구분
    incident_id = db.Column(db.Integer, db.ForeignKey('incidents.id'), nullable=False)

    name = db.Column(db.String(100), nullable=False) # 구호소명
    address = db.Column(db.String(200))
    phone = db.Column(db.String(20))
    area = db.Column(db.Integer)      # 면적
    capacity = db.Column(db.Integer)  # 수용 가능 인원
    is_active = db.Column(db.Boolean, default=True) # 운영 여부
    latitude = db.Column(db.Float)  # 위도
    longitude = db.Column(db.Float) # 경도

    # [관계 설정 유지]
    residents_logs = db.relationship('ResidentLog', backref='shelter', lazy=True)
    supplies = db.relationship('Supply', backref='shelter', lazy=True)
    duty_orders = db.relationship('DutyOrder', backref='shelter', lazy=True)
    staff_logs = db.relationship('StaffLog', backref='shelter', lazy=True)

    def __repr__(self):
        return f'<Shelter {self.name}>'


class AssemblyPoint(db.Model):
    """1차 집결지 (버스 정류장 등)"""
    __tablename__ = 'assembly_points'

    id = db.Column(db.Integer, primary_key=True)
    # [추가] 어떤 사고의 집결지인지 구분
    incident_id = db.Column(db.Integer, db.ForeignKey('incidents.id'), nullable=False)

    name = db.Column(db.String(100), nullable=False)
    address = db.Column(db.String(200))
    stop_no = db.Column(db.String(50)) # 정류장 번호 등 식별자
    is_active = db.Column(db.Boolean, default=True)
    latitude = db.Column(db.Float)
    longitude = db.Column(db.Float)

    # [관계 설정 유지]
    destinations = db.relationship('AssemblyDestination', backref='assembly_point', cascade="all, delete-orphan")


class AssemblyDestination(db.Model):
    """집결지와 구호소 간의 연결 테이블 (기존 유지)"""
    __tablename__ = 'assembly_destinations'

    id = db.Column(db.Integer, primary_key=True)
    assembly_id = db.Column(db.Integer, db.ForeignKey('assembly_points.id'), nullable=False)
    shelter_id = db.Column(db.Integer, db.ForeignKey('shelters.id'), nullable=False)
    
    waypoints = db.Column(db.Text, nullable=True)

    # [관계 설정 유지]
    target_shelter = db.relationship('Shelter', backref='assembly_sources')


# ==========================================
# 3. 이재민 관리 (Resident에 incident_id 추가)
# ==========================================
class Resident(db.Model):
    """이재민 정보"""
    __tablename__ = 'residents'

    id = db.Column(db.Integer, primary_key=True)
    # [추가] 어떤 사고의 이재민인지 구분
    incident_id = db.Column(db.Integer, db.ForeignKey('incidents.id'), nullable=False)
    shelter_id = db.Column(db.Integer, db.ForeignKey('shelters.id'), nullable=False)

    name = db.Column(db.String(50), nullable=False)
    phone = db.Column(db.String(20))
    gender = db.Column(db.String(10)) # '남', '여'
    age = db.Column(db.String(10))    # 생년월일 또는 나이
    village = db.Column(db.String(100)) # 거주 마을
    
    family_id = db.Column(db.String(50)) # 가족 그룹 ID
    family_role = db.Column(db.String(20)) # '세대주', '세대원'
    
    note = db.Column(db.Text) # 특이사항 (지병 등)
    kakao_id = db.Column(db.String(100)) # 카카오 연동 ID

    # [관계 설정 유지]
    logs = db.relationship('ResidentLog', backref='resident', lazy=True, cascade="all, delete-orphan")
    distributions = db.relationship('DistributionLog', backref='resident', lazy=True)

    def __repr__(self):
        return f'<Resident {self.name}>'


class ResidentLog(db.Model):
    """이재민 상태 변경 이력 (기존 유지)"""
    __tablename__ = 'resident_logs'

    id = db.Column(db.Integer, primary_key=True)
    incident_id = db.Column(db.Integer, db.ForeignKey('incidents.id'), nullable=False)
    resident_id = db.Column(db.Integer, db.ForeignKey('residents.id'), nullable=False)
    shelter_id = db.Column(db.Integer, db.ForeignKey('shelters.id'), nullable=False)
    
    status = db.Column(db.String(20), nullable=False) # IN, OUT, HOSPITAL
    log_content = db.Column(db.Text, nullable=True)
    log_time = db.Column(db.DateTime, default=datetime.now) # 상태 변경 시간


# ==========================================
# 4. 구호물품 관리 (기존 유지)
# ==========================================
class Supply(db.Model):
    """구호물품 재고 (기존 유지)"""
    __tablename__ = 'supplies'

    id = db.Column(db.Integer, primary_key=True)
    shelter_id = db.Column(db.Integer, db.ForeignKey('shelters.id'), nullable=True)
    item_name = db.Column(db.String(100), nullable=False)
    quantity = db.Column(db.Integer, default=0)

    # [관계 설정 유지]
    distributions = db.relationship('DistributionLog', backref='supply', lazy=True)

    def __repr__(self):
        return f'<Supply {self.item_name}>'


class DistributionLog(db.Model):
    """물품 지급 기록 (기존 유지)"""
    __tablename__ = 'distribution_logs'

    id = db.Column(db.Integer, primary_key=True)
    incident_id = db.Column(db.Integer, db.ForeignKey('incidents.id'), nullable=False)
    resident_id = db.Column(db.Integer, db.ForeignKey('residents.id'), nullable=False)
    supply_id = db.Column(db.Integer, db.ForeignKey('supplies.id'), nullable=False)
    quantity = db.Column(db.Integer, default=1)
    distributed_at = db.Column(db.DateTime, default=datetime.now)


class SupplyMovementLog(db.Model):
    """물품 배분 이력 (기존 유지)"""
    __tablename__ = 'supply_movement_logs'

    id = db.Column(db.Integer, primary_key=True)
    item_name = db.Column(db.String(100), nullable=False)
    incident_id = db.Column(db.Integer, db.ForeignKey('incidents.id'), nullable=False)
    to_shelter_id = db.Column(db.Integer, db.ForeignKey('shelters.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    moved_at = db.Column(db.DateTime, default=datetime.now)
    staff_name = db.Column(db.String(50))


# ==========================================
# 5. 근무자 및 근무 명령 관리 (기존 유지)
# ==========================================
class DutyOrder(db.Model):
    """사전 근무 명령서 (기존 유지)"""
    __tablename__ = 'duty_orders'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    dept = db.Column(db.String(50))
    phone = db.Column(db.String(20))
    mission = db.Column(db.String(100))
    incident_id = db.Column(db.Integer, db.ForeignKey('incidents.id'), nullable=False)
    shelter_id = db.Column(db.Integer, db.ForeignKey('shelters.id'), nullable=False)
    is_working = db.Column(db.Boolean, default=False)


class StaffLog(db.Model):
    """실제 근무 이력 (기존 유지)"""
    __tablename__ = 'staff_logs'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    name = db.Column(db.String(50), nullable=False)
    phone = db.Column(db.String(20))
    dept = db.Column(db.String(50))
    mission = db.Column(db.String(100))
    incident_id = db.Column(db.Integer, db.ForeignKey('incidents.id'), nullable=False)
    shelter_id = db.Column(db.Integer, db.ForeignKey('shelters.id'), nullable=False)
    
    login_time = db.Column(db.DateTime, default=datetime.now)
    logout_time = db.Column(db.DateTime, nullable=True)
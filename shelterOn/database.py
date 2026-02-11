import sqlite3
from datetime import datetime
from werkzeug.security import generate_password_hash

class ShelterOn:
    def __init__(self, db_name='shelter_on.db'):
        self.db_name = db_name
        self.init_db()

    def get_connection(self):
        conn = sqlite3.connect(self.db_name)
        # 외래키 제약 조건 활성화 (데이터 무결성 확보의 핵심)
        conn.execute("PRAGMA foreign_keys = ON;") 
        return conn

    def init_db(self):
        """시스템 운영에 필요한 모든 테이블 생성 및 컬럼 확인"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # 기존 residents 테이블에 family_id, family_role 추가
            try:
                
                cursor.execute('ALTER TABLE residents ADD COLUMN kakao_id TEXT')
                # 검색 및 조인 성능 향상을 위한 인덱스
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_resident_logs_resident_id ON resident_logs(resident_id)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_residents_name_phone ON residents(name, phone)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_supplies_shelter_id ON supplies(shelter_id)')
                conn.commit()
            except sqlite3.OperationalError:
                pass # 이미 컬럼이 존재하면 통과
                
            # 1. 구호소 테이블 
            cursor.execute('''CREATE TABLE IF NOT EXISTS shelters 
                (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                 name TEXT UNIQUE, 
                 address TEXT, 
                 phone TEXT, 
                 area REAL, 
                 capacity INTEGER, 
                 is_active INTEGER DEFAULT 1)''')
            
            # 2. 주민 기본 정보
            cursor.execute('''CREATE TABLE IF NOT EXISTS residents 
                (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, phone TEXT, village TEXT, 
                 gender TEXT, age TEXT, note TEXT, family_id TEXT, family_role TEXT DEFAULT "세대원", kakao_id TEXT)''')
            
            # 3. 입소/퇴소 로그
            cursor.execute('''CREATE TABLE IF NOT EXISTS resident_logs 
                (id INTEGER PRIMARY KEY AUTOINCREMENT, resident_id INTEGER, shelter_id INTEGER, 
                 status TEXT, log_time TEXT)''')

            # 4. 물품 관리
            cursor.execute('''CREATE TABLE IF NOT EXISTS supplies 
            (id INTEGER PRIMARY KEY AUTOINCREMENT, 
             shelter_id INTEGER, 
             item_name TEXT, 
             quantity INTEGER,
             FOREIGN KEY(shelter_id) REFERENCES shelters(id))''')

            # 5. 물품 배분 로그
            cursor.execute('''CREATE TABLE IF NOT EXISTS distribution_logs 
            (id INTEGER PRIMARY KEY AUTOINCREMENT, 
             resident_id INTEGER, 
             supply_id INTEGER, 
             shelter_id INTEGER, 
             quantity INTEGER, 
             distributed_at TEXT)''')
             
             # 6. 본부 -> 구호소 배분(이동) 이력 테이블
            cursor.execute('''CREATE TABLE IF NOT EXISTS supply_movement_logs 
                (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                 item_name TEXT, 
                 from_shelter_id INTEGER, -- NULL이면 본부
                 to_shelter_id INTEGER, 
                 quantity INTEGER, 
                 moved_at TEXT,
                 staff_name TEXT)''')
            conn.commit()
                 
            # 7. 집결지 테이블
            cursor.execute('''CREATE TABLE IF NOT EXISTS assembly_points 
                (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                 name TEXT UNIQUE, 
                 stop_no TEXT, 
                 address TEXT, 
                 is_active INTEGER DEFAULT 1)''')
            
            # 8. 집결지-구호소 연결 테이블
            cursor.execute('''CREATE TABLE IF NOT EXISTS assembly_destinations 
                (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                 assembly_id INTEGER, 
                 shelter_id INTEGER,
                 FOREIGN KEY(assembly_id) REFERENCES assembly_points(id),
                 FOREIGN KEY(shelter_id) REFERENCES shelters(id))''')
                 
            # 9. 사용자(관리자/근무자) 계정 테이블
            cursor.execute('''CREATE TABLE IF NOT EXISTS users 
                (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                 login_id TEXT UNIQUE, 
                 password TEXT, 
                 role_level INTEGER)''') # 1:관리자, 2:옵저버, 3:근무자

            # 10. 실시간 근무자 로그 (출퇴근 기록용)
            cursor.execute('''CREATE TABLE IF NOT EXISTS staff_logs 
            (id INTEGER PRIMARY KEY AUTOINCREMENT, 
             user_name TEXT, 
             user_phone TEXT, 
             dept TEXT, 
             mission TEXT, 
             shelter_id INTEGER, 
             login_time TEXT,
             logout_time TEXT, 
             FOREIGN KEY(shelter_id) REFERENCES shelters(id))''')

            # [신규] 11. 근무 명령서 (사전 등록된 근무자 정보)
            # is_working: 0(대기중), 1(근무중) -> 중복 로그인 방지
            cursor.execute('''CREATE TABLE IF NOT EXISTS duty_orders 
            (id INTEGER PRIMARY KEY AUTOINCREMENT, 
             name TEXT, 
             phone TEXT, 
             dept TEXT, 
             mission TEXT, 
             shelter_id INTEGER, 
             is_working INTEGER DEFAULT 0,
             FOREIGN KEY(shelter_id) REFERENCES shelters(id))''')
            
            # 기초 계정 생성 
            
            # 1:관리자, 2:모니터, 3:근무자
            admin_pw = generate_password_hash('dnjswkfur')
            monitor_pw = generate_password_hash('dnjswkfur')
            staff_pw = generate_password_hash('dnjswkfur')

            cursor.execute('INSERT OR IGNORE INTO users (login_id, password, role_level) VALUES (?, ?, ?)', ('admin', admin_pw, 1))
            cursor.execute('INSERT OR IGNORE INTO users (login_id, password, role_level) VALUES (?, ?, ?)', ('monitor', monitor_pw, 2))
            cursor.execute('INSERT OR IGNORE INTO users (login_id, password, role_level) VALUES (?, ?, ?)', ('staff', staff_pw, 3))
            
            conn.commit()

    def update_resident_status(self, resident_id, shelter_id, status):
        """주민의 상태(입소, 퇴소, 병원 등)를 업데이트하고 로그를 남김"""
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('INSERT INTO resident_logs (resident_id, shelter_id, status, log_time) VALUES (?, ?, ?, ?)',
                           (resident_id, shelter_id, status, now))
            conn.commit()

    def add_supply(self, item_name, quantity):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT id, quantity FROM supplies WHERE item_name = ?', (item_name,))
            existing = cursor.fetchone()
            if existing:
                cursor.execute('UPDATE supplies SET quantity = ? WHERE id = ?', (existing[1] + int(quantity), existing[0]))
            else:
                cursor.execute('INSERT INTO supplies (item_name, quantity) VALUES (?, ?)', (item_name, quantity))

    def distribute_supply(self, resident_id, supply_id, quantity):
        """트랜잭션을 적용하여 재고 차감과 로그 기록을 원자적으로 처리"""
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                # 1. 현재 재고 확인 (성능 및 무결성)
                cursor.execute('SELECT quantity FROM supplies WHERE id = ?', (supply_id,))
                current_qty = cursor.fetchone()
                
                if current_qty and current_qty[0] >= quantity:
                    # 2. 재고 차감
                    cursor.execute('UPDATE supplies SET quantity = quantity - ? WHERE id = ?', (quantity, supply_id))
                    # 3. 배분 기록
                    cursor.execute('''INSERT INTO distribution_logs (resident_id, supply_id, quantity, distributed_at) 
                                      VALUES (?, ?, ?, ?)''', (resident_id, supply_id, quantity, now))
                    conn.commit()
                else:
                    raise ValueError("재고가 부족합니다.")
        except Exception as e:
            print(f"Error during distribution: {e}")
            # with 블록이 자동으로 rollback을 수행하지만 명시적 에러 처리가 중요함

    def cancel_distribution(self, log_id):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT supply_id, quantity FROM distribution_logs WHERE id = ?', (log_id,))
            log = cursor.fetchone()
            if log:
                supply_id, qty = log[0], log[1]
                cursor.execute('UPDATE supplies SET quantity = quantity + ? WHERE id = ?', (qty, supply_id))
                cursor.execute('DELETE FROM distribution_logs WHERE id = ?', (log_id,))
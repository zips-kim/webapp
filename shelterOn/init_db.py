from app import app
from models import db, User, Shelter, Supply
from werkzeug.security import generate_password_hash

# 앱 컨텍스트 안에서 DB 작업 수행
with app.app_context():
    # 1. 테이블 새로 만들기
    db.create_all()
    print("✅ 데이터베이스 테이블 생성 완료")

    # 2. 관리자 계정 생성 (비밀번호 암호화 필수!)
    # 기존에 계정이 있으면 중복 에러가 날 수 있으니 체크
    if not User.query.filter_by(login_id='admin').first():
        admin = User(
            login_id='admin',
            password=generate_password_hash('1234'), # 원하는 비밀번호 입력
            role_level=1
        )
        db.session.add(admin)
        print("✅ 관리자 계정(admin/1234) 생성 완료")

    # 3. 테스트용 구호소 및 물품 생성
    if not Shelter.query.first():
        sh = Shelter(name="유성종합스포츠센터", address="유성대로 978", capacity=500, is_active=True)
        db.session.add(sh)
        db.session.commit() # 구호소 ID 생성을 위해 먼저 커밋
        
        # 본부 물품 생성
        sup = Supply(item_name="생수(500ml)", quantity=1000, shelter_id=None)
        db.session.add(sup)
        # 구호소 물품 생성
        sup2 = Supply(item_name="담요", quantity=50, shelter_id=sh.id)
        db.session.add(sup2)
        print("✅ 기초 데이터(구호소, 물품) 생성 완료")

    db.session.commit()
    print("🎉 DB 초기화 완료! 이제 앱을 실행하고 로그인해 보세요.")
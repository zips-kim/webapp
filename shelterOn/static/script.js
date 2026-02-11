// 실시간 테이블 필터 함수
function filterTable(inputId, tableId) {
    const input = document.getElementById(inputId);
    const filter = input.value.toUpperCase();
    const table = document.getElementById(tableId);
    const tr = table.getElementsByTagName("tr");

    for (let i = 1; i < tr.length; i++) {
        let display = false;
        const tds = tr[i].getElementsByTagName("td");
        for (let j = 0; j < tds.length; j++) {
            if (tds[j]) {
                const text = tds[j].textContent || tds[j].innerText;
                if (text.toUpperCase().indexOf(filter) > -1) {
                    display = true;
                    break;
                }
            }
        }
        tr[i].style.display = display ? "" : "none";
    }
}

// 모달 제어 함수
function openModal(id) { document.getElementById(id).style.display = "block"; }
function closeModal(id) { document.getElementById(id).style.display = "none"; }

// 배경 클릭 시 팝업 닫기
window.onclick = function(event) {
    if (event.target.className === 'modal') {
        event.target.style.display = "none";
    }
}

function openTab(tabName) {
    var i;
    // 모든 탭 내용을 숨김
    var x = document.getElementsByClassName("admin-tab-content");
    for (i = 0; i < x.length; i++) {
        x[i].style.display = "none";
    }
    
    // 선택한 탭만 보여줌
    document.getElementById(tabName).style.display = "block";
    
    // 모든 버튼에서 active 클래스 제거
    var buttons = document.getElementsByClassName("tab-button");
    for (i = 0; i < buttons.length; i++) {
        buttons[i].classList.remove("active");
    }
    
    // 현재 클릭한 버튼에 active 클래스 추가
    event.currentTarget.classList.add("active");
}

// 특정 구호소를 미리 선택하여 모달을 여는 함수
function openModalWithShelter(modalId, shelterId) {
	// 1. 모달 열기
	document.getElementById(modalId).style.display = "block";
	
	// 2. [핵심] 해당 구호소 ID를 hidden input에 저장
	const shelterInput = document.getElementById('shelterIdInput');
	if (shelterInput) {
		shelterInput.value = shelterId;
		console.log("선택된 구호소 ID:", shelterId); // 디버깅용
	}
}

// 주민 상세보기 모달 열기
function showResidentDetail(name, gender, age, phone, village, shelterId, shelter, note, supplies) {
    document.getElementById('detName').innerText = "👤 " + name + " 님 상세 정보";
    document.getElementById('detGender').innerText = gender;
    document.getElementById('detAge').innerText = age;
	document.getElementById('detPhone').innerText = phone;
    document.getElementById('detVillage').innerText = village;
    document.getElementById('detShelter').innerText = shelter;
    document.getElementById('detSupplies').innerText = supplies;
    document.getElementById('detNote').innerText = note;
    
    document.getElementById('detailModal').style.display = "block";
}

// 기존 closeModal 함수가 없다면 아래 코드도 추가
function closeModal(modalId) {
    document.getElementById(modalId).style.display = "none";
}

function toggleMenu() {
    const navLinks = document.getElementById('navLinks');
    navLinks.classList.toggle('show');
}

// 메뉴 바깥 클릭 시 닫기 기능 수정
window.addEventListener('click', function(e) {
    const navLinks = document.getElementById('navLinks');
    const menuToggle = document.querySelector('.menu-toggle');

    // navLinks가 존재하고, menuToggle이 존재할 때만 contains 체크를 수행합니다.
    if (navLinks && menuToggle) {
        if (!menuToggle.contains(e.target) && !navLinks.contains(e.target)) {
            navLinks.classList.remove('show');
        }
    }
});



// 상태 업데이트 함수
async function updateStatus(residentId, status) {
    const msg = status === 'HOSPITAL' ? "병원 후송 처리를 하시겠습니까?" : "퇴소 처리를 하시겠습니까?";
    if(!confirm(msg)) return;

    const response = await fetch('/api/resident/status', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ id: residentId, status: status })
    });
    if(response.ok) { alert("처리되었습니다."); location.reload(); }
}

// 물품 배분 함수
async function giveSupply(residentId) {
    const supplyId = document.getElementById(`supply_${residentId}`).value;
    const response = await fetch('/api/supply/distribute', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ resident_id: residentId, supply_id: supplyId, quantity: 1 })
    });
    if(response.ok) alert("물품이 전달되었습니다.");
}



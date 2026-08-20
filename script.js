// Переключение видимости пароля
const passwordInput = document.getElementById('password');
const toggleBtn = document.getElementById('togglePassword');

toggleBtn.addEventListener('click', () => {
    if (passwordInput.type === 'password') {
        passwordInput.type = 'text';
        toggleBtn.textContent = '🙈';
    } else {
        passwordInput.type = 'password';
        toggleBtn.textContent = '👁️';
    }
});

// Проверка пароля
const checkBtn = document.getElementById('checkBtn');
const loading = document.getElementById('loading');
const result = document.getElementById('result');

checkBtn.addEventListener('click', checkPassword);
passwordInput.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') {
        checkPassword();
    }
});

async function checkPassword() {
    const password = passwordInput.value;
    
    if (!password) {
        alert('Введите пароль!');
        return;
    }
    
    // Показываем загрузку
    loading.style.display = 'block';
    result.style.display = 'none';
    checkBtn.disabled = true;
    
    try {
        const response = await fetch('/check', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ password })
        });
        
        const data = await response.json();
        
        if (data.error) {
            alert(data.error);
            return;
        }
        
        displayResult(data);
        
    } catch (error) {
        alert('Ошибка при проверке пароля');
        console.error(error);
    } finally {
        loading.style.display = 'none';
        checkBtn.disabled = false;
    }
}

function displayResult(data) {
    // Оценка
    document.getElementById('rating').textContent = data.overall_rating;
    document.getElementById('score').textContent = data.strength_score;
    
    // Метрики
    document.getElementById('length').textContent = data.length + ' символов';
    document.getElementById('entropy').textContent = data.entropy + ' бит';
    document.getElementById('checks').textContent = `${data.checks_passed}/${data.total_checks}`;
    
    // Время взлома
    const crackTimesDiv = document.getElementById('crackTimes');
    crackTimesDiv.innerHTML = '';
    for (const [attack, time] of Object.entries(data.crack_time_estimates)) {
        const item = document.createElement('div');
        item.className = 'crack-time-item';
        item.innerHTML = `<span>${attack}</span><strong>${time}</strong>`;
        crackTimesDiv.appendChild(item);
    }
    
    // Онлайн-проверки
    const onlineChecksDiv = document.getElementById('onlineChecks');
    onlineChecksDiv.innerHTML = '';
    for (const [source, check] of Object.entries(data.online_checks)) {
        const item = document.createElement('div');
        item.className = 'check-item';
        
        let icon = '⚠️';
        if (check.status === 'clean') icon = '✅';
        else if (check.status === 'found') icon = '❌';
        
        item.innerHTML = `
            <span class="check-icon">${icon}</span>
            <span><strong>${source.replace(/_/g, ' ')}</strong>: ${check.message}</span>
        `;
        onlineChecksDiv.appendChild(item);
    }
    
    // Уязвимости
    const vulnSection = document.getElementById('vulnerabilitiesSection');
    const vulnList = document.getElementById('vulnerabilities');
    if (data.vulnerabilities.length > 0) {
        vulnSection.style.display = 'block';
        vulnList.innerHTML = '';
        data.vulnerabilities.forEach(v => {
            const li = document.createElement('li');
            li.textContent = v;
            vulnList.appendChild(li);
        });
    } else {
        vulnSection.style.display = 'none';
    }
    
    // Рекомендации
    const recSection = document.getElementById('recommendationsSection');
    const recList = document.getElementById('recommendations');
    if (data.recommendations.length > 0) {
        recSection.style.display = 'block';
        recList.innerHTML = '';
        data.recommendations.forEach(r => {
            const li = document.createElement('li');
            li.textContent = r;
            recList.appendChild(li);
        });
    } else {
        recSection.style.display = 'none';
    }
    
    // Показываем результат
    result.style.display = 'block';
}
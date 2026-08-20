from flask import Flask, render_template, request, jsonify
from password_check import UltimatePasswordAnalyzer
import logging

app = Flask(__name__)
analyzer = UltimatePasswordAnalyzer()

# Отключаем лишние логи
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

@app.route('/')
def index():
    """Главная страница"""
    return render_template('index.html')

@app.route('/check', methods=['POST'])
def check_password():
    """Проверка пароля"""
    try:
        data = request.get_json()
        password = data.get('password', '')
        
        if not password:
            return jsonify({'error': 'Введите пароль'}), 400
        
        # Анализируем пароль
        result = analyzer.analyze_ultimate(password)
        
        # Убираем пароль из результата для безопасности
        safe_result = {
            'overall_rating': result['overall_rating'],
            'strength_score': result['strength_score'],
            'max_score': result['max_score'],
            'length': result['length'],
            'entropy': round(result['entropy'], 1),
            'crack_time_estimates': result['crack_time_estimates'],
            'vulnerabilities': result['vulnerabilities'],
            'recommendations': result['recommendations'],
            'online_checks': result['online_checks'],
            'checks_passed': result['checks_passed'],
            'total_checks': result['total_checks']
        }
        
        return jsonify(safe_result)
    
    except Exception as e:
        return jsonify({'error': f'Ошибка при проверке: {str(e)}'}), 500

if __name__ == '__main__':
    print("🔐 Сервер запущен!")
    print("🌐 Открой браузер и зайди на: http://localhost:5000")
    app.run(debug=False, host='0.0.0.0', port=5000)
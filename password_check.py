import hashlib
import requests
import re
import math
from typing import Dict, List


class UltimatePasswordAnalyzer:
    """Ультимативный анализатор паролей v4.0"""

    KEYBOARD_PATTERNS = [
        'qwerty', 'qwertyuiop', 'asdfgh', 'asdfghjkl', 'zxcvbn', 'zxcvbnm',
        '1234567890', '0987654321', 'qaz', 'wsx', 'edc', 'rfv', 'tgb', 'yhn', 'ujm',
        '147', '258', '369', '741', '852', '963', 'qwe', 'asd', 'zxc',
        'ytrewq', 'hgfdsa', 'mnbvcx', 'qazwsx', 'wsxedc', 'edcrfv', 'rfvtgb',
        '!@#$%', '@#$%^', '#$%^&', '$%^&*', '%^&*(',
        '1qaz', '2wsx', '3edc', '4rfv', '5tgb', '6yhn', '7ujm',
    ]

    COMMON_WORDS = [
        'password', '123456', '12345678', 'qwerty', 'abc123', 'monkey', 'master',
        'dragon', '111111', 'baseball', 'iloveyou', 'trustno1', 'sunshine',
        'princess', 'football', 'shadow', 'superman', 'michael', 'password1',
        'admin', 'administrator', 'root', 'user', 'guest', 'test', 'login',
        'welcome', 'letmein', 'access', 'hello', 'charlie', 'donald', 'batman',
        'love', 'god', 'sex', 'money', 'power', 'angel', 'friend',
        'john', 'david', 'james', 'robert', 'william', 'richard',
        'apple', 'google', 'facebook', 'amazon', 'microsoft', 'netflix',
        'instagram', 'twitter', 'youtube', 'whatsapp', 'telegram',
        'basketball', 'soccer', 'hockey', 'tennis',
        'phoenix', 'tiger', 'eagle', 'lion', 'wolf', 'bear',
        'hacker', 'cyber', 'security', 'linux', 'windows', 'android', 'iphone',
        'january', 'february', 'march', 'april', 'june', 'july',
        'august', 'september', 'october', 'november', 'december',
        'red', 'blue', 'green', 'yellow', 'black', 'white', 'purple',
        'russia', 'moscow', 'america', 'london', 'paris', 'berlin',
    ]

    LEET_SPEAK = {
        'a': ['4', '@'], 'b': ['8'], 'e': ['3'],
        'g': ['9', '6'], 'i': ['1', '!'], 'l': ['1', '|'], 'o': ['0'],
        's': ['5', '$'], 't': ['7', '+'], 'z': ['2'],
    }

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'UltimatePasswordChecker/4.0'
        })

    # ==================== ЛОКАЛЬНЫЕ ПРОВЕРКИ ====================

    def _check_length(self, password: str) -> Dict:
        length = len(password)
        score = 0
        vulnerabilities = []
        recommendations = []
        passed = False

        if length >= 20:
            score = 15
            passed = True
        elif length >= 16:
            score = 12
            passed = True
        elif length >= 12:
            score = 8
            passed = True
        elif length >= 8:
            score = 4
            recommendations.append("🔹 Увеличь длину до 12+ символов")
        else:
            vulnerabilities.append("❌ Критически короткий пароль (менее 8 символов)")
            recommendations.append("🔹 Минимальная длина: 12 символов")

        return {'score': score, 'passed': passed, 'vulnerabilities': vulnerabilities, 'recommendations': recommendations}

    def _check_complexity(self, password: str) -> Dict:
        score = 0
        vulnerabilities = []
        recommendations = []

        has_lower = bool(re.search(r'[a-z]', password))
        has_upper = bool(re.search(r'[A-Z]', password))
        has_digit = bool(re.search(r'\d', password))
        has_special = bool(re.search(r'[!@#$%^&*(),.?":{}|<>_\-\[\]\\;\',./`~]', password))
        has_unicode = bool(re.search(r'[^\x00-\x7F]', password))

        char_types = sum([has_lower, has_upper, has_digit, has_special, has_unicode])

        if char_types >= 5:
            score = 20
        elif char_types == 4:
            score = 15
        elif char_types == 3:
            score = 10
        elif char_types == 2:
            score = 5
            recommendations.append("🔹 Добавь больше типов символов")
        else:
            vulnerabilities.append("❌ Только один тип символов")
            recommendations.append("🔹 Используй строчные, заглавные, цифры и спецсимволы")

        if not has_upper:
            recommendations.append("🔹 Добавь заглавные буквы (A-Z)")
        if not has_lower:
            recommendations.append("🔹 Добавь строчные буквы (a-z)")
        if not has_digit:
            recommendations.append("🔹 Добавь цифры (0-9)")
        if not has_special:
            recommendations.append("🔹 Добавь спецсимволы (!@#$%^&*)")

        return {'score': score, 'passed': char_types >= 4, 'vulnerabilities': vulnerabilities, 'recommendations': recommendations}

    def _check_keyboard_patterns(self, password: str) -> Dict:
        password_lower = password.lower()
        score = 0
        vulnerabilities = []
        passed = True

        for pattern in self.KEYBOARD_PATTERNS:
            if pattern in password_lower:
                vulnerabilities.append(f"❌ Клавиатурный паттерн: '{pattern}'")
                passed = False
                break

        if passed:
            score = 10

        return {'score': score, 'passed': passed, 'vulnerabilities': vulnerabilities, 'recommendations': ["🔹 Избегай последовательностей клавиш"] if not passed else []}

    def _check_dictionary_words(self, password: str) -> Dict:
        password_lower = password.lower()
        score = 0
        vulnerabilities = []
        passed = True

        for word in self.COMMON_WORDS:
            if len(word) >= 4 and word in password_lower:
                vulnerabilities.append(f"❌ Популярное слово: '{word}'")
                passed = False
                break

        if passed:
            score = 10

        return {'score': score, 'passed': passed, 'vulnerabilities': vulnerabilities, 'recommendations': ["🔹 Не используй словарные слова"] if not passed else []}

    def _check_repeating_patterns(self, password: str) -> Dict:
        score = 0
        vulnerabilities = []
        passed = True

        if re.search(r'(.)\1{2,}', password):
            vulnerabilities.append("❌ Повторяющиеся символы (aaa, 111)")
            passed = False

        for i in range(2, len(password) // 2 + 1):
            pattern = password[:i]
            if len(pattern) >= 2 and password.count(pattern) > 1:
                vulnerabilities.append(f"❌ Повторяющийся паттерн: '{pattern}'")
                passed = False
                break

        if passed:
            score = 8

        return {'score': score, 'passed': passed, 'vulnerabilities': vulnerabilities, 'recommendations': ["🔹 Избегай повторов"] if not passed else []}

    def _check_sequential_chars(self, password: str) -> Dict:
        score = 0
        vulnerabilities = []
        passed = True

        for i in range(len(password) - 2):
            if ord(password[i]) + 1 == ord(password[i+1]) and ord(password[i+1]) + 1 == ord(password[i+2]):
                vulnerabilities.append("❌ Возрастающая последовательность (abc, 123)")
                passed = False
                break
            if ord(password[i]) - 1 == ord(password[i+1]) and ord(password[i+1]) - 1 == ord(password[i+2]):
                vulnerabilities.append("❌ Убывающая последовательность (cba, 321)")
                passed = False
                break

        if passed:
            score = 7

        return {'score': score, 'passed': passed, 'vulnerabilities': vulnerabilities, 'recommendations': ["🔹 Избегай последовательностей"] if not passed else []}

    def _check_leet_speak(self, password: str) -> Dict:
        score = 0
        vulnerabilities = []
        passed = True

        decoded = password.lower()
        for letter, replacements in self.LEET_SPEAK.items():
            for repl in replacements:
                decoded = decoded.replace(repl, letter)

        for word in self.COMMON_WORDS[:50]:
            if len(word) >= 4 and word in decoded:
                vulnerabilities.append(f"❌ Leet Speak: '{word}'")
                passed = False
                break

        if passed:
            score = 5

        return {'score': score, 'passed': passed, 'vulnerabilities': vulnerabilities, 'recommendations': ["🔹 Замены @=a, 3=e не защищают"] if not passed else []}

    def _check_dates_and_years(self, password: str) -> Dict:
        score = 0
        vulnerabilities = []
        passed = True

        for year in range(1900, 2100):
            if str(year) in password:
                vulnerabilities.append(f"❌ Содержит год: {year}")
                passed = False
                break

        if re.search(r'(0[1-9]|1[0-9]|2[0-9]|3[0-1])(0[1-9]|1[0-2])', password):
            vulnerabilities.append("❌ Содержит дату (DDMM)")
            passed = False

        if passed:
            score = 5

        return {'score': score, 'passed': passed, 'vulnerabilities': vulnerabilities, 'recommendations': ["🔹 Не используй даты и годы"] if not passed else []}

    def _check_common_substitutions(self, password: str) -> Dict:
        score = 0
        vulnerabilities = []
        passed = True

        common_subs = ['p@ssw0rd', 'p@ssword', 'adm1n', 'l0g1n', 'w3lcome', 'l3tm31n']
        password_lower = password.lower()

        for sub in common_subs:
            if sub in password_lower:
                vulnerabilities.append(f"❌ Популярная замена: '{sub}'")
                passed = False
                break

        if passed:
            score = 5

        return {'score': score, 'passed': passed, 'vulnerabilities': vulnerabilities, 'recommendations': ["🔹 Избегай популярных замен"] if not passed else []}

    def _check_palindromes(self, password: str) -> Dict:
        score = 0
        vulnerabilities = []
        passed = True

        for i in range(len(password) - 3):
            for j in range(i + 4, min(i + 10, len(password) + 1)):
                substr = password[i:j]
                if substr == substr[::-1]:
                    vulnerabilities.append(f"❌ Палиндром: '{substr}'")
                    passed = False
                    break
            if not passed:
                break

        if passed:
            score = 3

        return {'score': score, 'passed': passed, 'vulnerabilities': vulnerabilities, 'recommendations': ["🔹 Избегай палиндромов"] if not passed else []}

    def _check_entropy(self, password: str) -> Dict:
        entropy_result = self._calculate_advanced_entropy(password)
        entropy = entropy_result['entropy']
        score = 0
        vulnerabilities = []
        passed = entropy >= 60

        if entropy >= 80:
            score = 10
        elif entropy >= 60:
            score = 7
        elif entropy >= 40:
            score = 4
            vulnerabilities.append("⚠️ Низкая энтропия")
        else:
            vulnerabilities.append("❌ Критически низкая энтропия")

        return {'score': score, 'passed': passed, 'vulnerabilities': vulnerabilities, 'recommendations': ["🔹 Увеличь разнообразие символов"] if not passed else []}

    def _check_uniqueness(self, password: str) -> Dict:
        score = 0
        vulnerabilities = []
        passed = True

        unique_chars = len(set(password))
        total_chars = len(password)
        ratio = unique_chars / total_chars if total_chars > 0 else 0

        if ratio >= 0.8:
            score = 5
        elif ratio >= 0.6:
            score = 3
        else:
            vulnerabilities.append("⚠️ Мало уникальных символов")
            passed = False

        return {'score': score, 'passed': passed, 'vulnerabilities': vulnerabilities, 'recommendations': ["🔹 Используй больше уникальных символов"] if not passed else []}

    # ==================== РАСЧЕТЫ ====================

    def _calculate_advanced_entropy(self, password: str) -> Dict:
        charset_size = 0
        if re.search(r'[a-z]', password):
            charset_size += 26
        if re.search(r'[A-Z]', password):
            charset_size += 26
        if re.search(r'\d', password):
            charset_size += 10
        if re.search(r'[!@#$%^&*(),.?":{}|<>_\-\[\]\\;\',./`~]', password):
            charset_size += 32
        if re.search(r'[^\x00-\x7F]', password):
            charset_size += 100

        if charset_size == 0:
            return {'entropy': 0, 'charset_size': 0, 'effective_length': 0}

        entropy = len(password) * math.log2(charset_size)
        unique_ratio = len(set(password)) / len(password) if len(password) > 0 else 0
        effective_length = len(password) * unique_ratio

        return {'entropy': entropy, 'charset_size': charset_size, 'effective_length': effective_length}

    def _estimate_crack_times(self, entropy: float) -> Dict:
        estimates = {}
        scenarios = {
            'Офлайн (GPU-ферма)': 100_000_000_000,
            'Офлайн (CPU)': 1_000_000_000,
            'Онлайн (быстрый)': 1_000,
            'Онлайн (медленный)': 10,
        }
        for name, speed in scenarios.items():
            seconds = (2 ** entropy) / speed
            estimates[name] = self._format_time(seconds)
        return estimates

    def _format_time(self, seconds: float) -> str:
        if seconds < 1:
            return "Мгновенно"
        elif seconds < 60:
            return f"{int(seconds)} сек"
        elif seconds < 3600:
            return f"{int(seconds / 60)} мин"
        elif seconds < 86400:
            return f"{int(seconds / 3600)} часов"
        elif seconds < 31536000:
            return f"{int(seconds / 86400)} дней"
        elif seconds < 31536000 * 1000:
            return f"{int(seconds / 31536000)} лет"
        elif seconds < 31536000 * 1_000_000:
            return f"{int(seconds / 31536000 / 1000)} тыс. лет"
        elif seconds < 31536000 * 1_000_000_000:
            return f"{int(seconds / 31536000 / 1_000_000)} млн лет"
        else:
            return "Миллиарды лет"

    # ==================== ОНЛАЙН ПРОВЕРКИ ====================

    def _check_all_online_sources(self, password: str) -> Dict:
        checks = {}
        print("  [1/4] Have I Been Pwned...")
        checks['have_i_been_pwned'] = self._check_hibp(password)
        print("  [2/4] Weakpass...")
        checks['weakpass'] = self._check_weakpass(password)
        print("  [3/4] NIST Top-100k...")
        checks['nist_top_100k'] = self._check_nist(password)
        print("  [4/4] MD5/SHA хеш-базы...")
        checks['hash_lookup'] = self._check_hash_databases(password)
        return checks

    def _check_hibp(self, password: str) -> Dict:
        try:
            sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
            prefix = sha1_hash[:5]
            suffix = sha1_hash[5:]

            response = self.session.get(f"https://api.pwnedpasswords.com/range/{prefix}", timeout=8)
            response.raise_for_status()

            for line in response.text.split('\r\n'):
                if ':' in line:
                    h, count = line.split(':')
                    if h == suffix:
                        return {'status': 'found', 'count': int(count), 'message': f'Найден в {count} утечках!'}

            return {'status': 'clean', 'count': 0, 'message': 'Не найден'}
        except Exception as e:
            return {'status': 'error', 'count': 0, 'message': f'Ошибка: {str(e)[:50]}'}

    def _check_weakpass(self, password: str) -> Dict:
        try:
            md5_hash = hashlib.md5(password.encode('utf-8')).hexdigest()
            response = self.session.get(f"https://weakpass.com/api/v1/search/{md5_hash}", timeout=8)

            if response.status_code == 200:
                data = response.json()
                if data.get('passwords'):
                    return {'status': 'found', 'count': len(data['passwords']), 'message': 'Найден в базе слабых паролей'}

            return {'status': 'clean', 'count': 0, 'message': 'Не найден'}
        except Exception as e:
            return {'status': 'error', 'count': 0, 'message': f'Ошибка: {str(e)[:50]}'}

    def _check_nist(self, password: str) -> Dict:
        try:
            response = self.session.get(
                "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-100000.txt",
                timeout=15
            )
            if response.status_code == 200:
                bad_list = response.text.lower().split('\n')
                if password.lower() in bad_list:
                    return {'status': 'found', 'count': 1, 'message': 'В топ-100000 худших паролей!'}

            return {'status': 'clean', 'count': 0, 'message': 'Не в топ-100000'}
        except Exception as e:
            return {'status': 'error', 'count': 0, 'message': f'Ошибка: {str(e)[:50]}'}

    def _check_hash_databases(self, password: str) -> Dict:
        try:
            md5_hash = hashlib.md5(password.encode('utf-8')).hexdigest()
            sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest()

            # Проверка через cmd5-подобные сервисы
            response = self.session.get(
                f"https://www.md5online.org/md5-decrypt.html",
                params={'hash': md5_hash},
                timeout=8
            )

            # Альтернативная проверка через Nitrxgen
            response2 = self.session.get(
                f"https://www.nitrxgen.net/md5db/{md5_hash}",
                timeout=8
            )

            if response2.status_code == 200 and response2.text:
                return {'status': 'found', 'count': 1, 'message': 'MD5 хеш найден в базе'}

            return {'status': 'clean', 'count': 0, 'message': 'Хеши не найдены'}
        except Exception as e:
            return {'status': 'error', 'count': 0, 'message': f'Ошибка: {str(e)[:50]}'}

    # ==================== ГЛАВНЫЙ АНАЛИЗ ====================

    def analyze_ultimate(self, password: str) -> Dict:
        result = {
            'length': len(password),
            'strength_score': 0,
            'max_score': 100,
            'entropy': 0.0,
            'crack_time_estimates': {},
            'vulnerabilities': [],
            'online_checks': {},
            'recommendations': [],
            'detailed_metrics': {},
            'overall_rating': '',
            'checks_passed': 0,
            'total_checks': 0
        }

        # Локальные проверки
        local_checks = [
            self._check_length,
            self._check_complexity,
            self._check_keyboard_patterns,
            self._check_dictionary_words,
            self._check_repeating_patterns,
            self._check_sequential_chars,
            self._check_leet_speak,
            self._check_dates_and_years,
            self._check_common_substitutions,
            self._check_palindromes,
            self._check_entropy,
            self._check_uniqueness,
        ]

        for check in local_checks:
            r = check(password)
            result['strength_score'] += r['score']
            result['vulnerabilities'].extend(r.get('vulnerabilities', []))
            result['recommendations'].extend(r.get('recommendations', []))
            result['checks_passed'] += 1 if r['passed'] else 0
            result['total_checks'] += 1

        # Энтропия
        entropy_result = self._calculate_advanced_entropy(password)
        result['entropy'] = entropy_result['entropy']
        result['detailed_metrics'] = entropy_result

        # Время взлома
        result['crack_time_estimates'] = self._estimate_crack_times(entropy_result['entropy'])

        # Онлайн проверки
        print("\n🌐 ОНЛАЙН-ПРОВЕРКИ:")
        result['online_checks'] = self._check_all_online_sources(password)

        # Штраф за утечки
        total_breaches = sum(
            v.get('count', 0) for v in result['online_checks'].values()
            if isinstance(v, dict) and isinstance(v.get('count'), int)
        )
        if total_breaches > 0:
            result['strength_score'] = max(0, result['strength_score'] - 30)

        # Финальная оценка
        if total_breaches > 0:
            result['overall_rating'] = f"🚨 КРИТИЧЕСКИЙ: Найден в {total_breaches} утечках!"
        elif result['strength_score'] >= 85:
            result['overall_rating'] = "🟢 ОТЛИЧНЫЙ: Максимальная защита"
        elif result['strength_score'] >= 70:
            result['overall_rating'] = "🟡 ХОРОШИЙ: Надежный пароль"
        elif result['strength_score'] >= 50:
            result['overall_rating'] = "🟠 СРЕДНИЙ: Требует улучшения"
        else:
            result['overall_rating'] = "🔴 СЛАБЫЙ: Немедленно замени!"

        return result


# ==================== ГЛАВНАЯ ФУНКЦИЯ ====================

def main():
    print("=" * 70)
    print("🔐 УЛЬТИМАТИВНЫЙ АНАЛИЗАТОР ПАРОЛЕЙ v4.0")
    print("=" * 70)
    print("12 локальных проверок | 4 онлайн-API | Максимальная защита")
    print("=" * 70)

    analyzer = UltimatePasswordAnalyzer()

    while True:
        password = input("\n🔑 Введите пароль (или 'quit' для выхода): ")

        if password.lower() == 'quit':
            print("\n👋 До свидания!")
            break

        if not password:
            print("❌ Пароль не может быть пустым!")
            continue

        print("\n⏳ Анализ...")
        result = analyzer.analyze_ultimate(password)

        # Вывод
        print("\n" + "=" * 70)
        print("📊 РЕЗУЛЬТАТЫ")
        print("=" * 70)

        print(f"\n🎯 Оценка: {result['overall_rating']}")
        print(f"📈 Баллы: {result['strength_score']}/{result['max_score']}")
        print(f"✅ Проверок пройдено: {result['checks_passed']}/{result['total_checks']}")
        print(f"📏 Длина: {result['length']} символов")
        print(f"🎲 Энтропия: {result['entropy']:.1f} бит")

        print("\n⏱️  ВРЕМЯ ВЗЛОМА:")
        print("-" * 50)
        for attack, t in result['crack_time_estimates'].items():
            print(f"  {attack:25} : {t}")

        print("\n🌐 ОНЛАЙН-ПРОВЕРКИ:")
        print("-" * 50)
        for source, data in result['online_checks'].items():
            icon = "✅" if data['status'] == 'clean' else "❌" if data['status'] == 'found' else "⚠️"
            print(f"  {icon} {source:25} : {data['message']}")

        if result['vulnerabilities']:
            print("\n⚠️  УЯЗВИМОСТИ:")
            print("-" * 50)
            for v in result['vulnerabilities']:
                print(f"  {v}")

        if result['recommendations']:
            print("\n💡 РЕКОМЕНДАЦИИ:")
            print("-" * 50)
            seen = set()
            for r in result['recommendations']:
                if r not in seen:
                    print(f"  {r}")
                    seen.add(r)

        print("\n" + "=" * 70)


if __name__ == "__main__":
    main()
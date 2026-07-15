import re
import hashlib
import getpass
import secrets
import string

def generate_strong_password(length=16):
    """
    Генерация случайного надежного пароля
    """
    # Определяем наборы символов
    lowercase = string.ascii_lowercase
    uppercase = string.ascii_uppercase
    digits = string.digits
    symbols = "!@#$%^&*()_+-=[]{};:'\",.<>/?\\|"
    
    # Гарантируем наличие хотя бы одного символа из каждого набора
    password_chars = [
        secrets.choice(lowercase),
        secrets.choice(uppercase),
        secrets.choice(digits),
        secrets.choice(symbols)
    ]
    
    # Добавляем остальные символы случайным образом
    all_chars = lowercase + uppercase + digits + symbols
    for _ in range(length - 4):
        password_chars.append(secrets.choice(all_chars))
    
    # Перемешиваем символы
    secrets.SystemRandom().shuffle(password_chars)
    
    return ''.join(password_chars)

def check_password(password):
    score = 0
    errors = []
    suggestions = []
    
    if len(password) >= 8:
        score += 1
    else:
        errors.append("минимум 8 символов")
        if len(password) < 4:
            suggestions.append("попробуйте фразу из 3-4 слов")
        else:
            suggestions.append("добавьте еще 2-3 символа")
    
    if len(password) >= 12:
        score += 1
    else:
        suggestions.append("для большей надежности используйте 12+ символов")
    
    if re.search(r'[A-Z]', password) and re.search(r'[a-z]', password):
        score += 1
    else:
        errors.append("нужны заглавные и строчные буквы")
        if not re.search(r'[A-Z]', password):
            suggestions.append("добавьте заглавную букву в начале или середине")
        if not re.search(r'[a-z]', password):
            suggestions.append("добавьте строчные буквы")
    
    if re.search(r'\d', password):
        score += 1
    else:
        errors.append("нужна хотя бы одна цифра")
        suggestions.append("замените букву на похожую цифру (например, O на 0)")
    
    if re.search(r'[!@#$%^&*()_+\-=\[\]{};:\'",.<>/?\\|]', password):
        score += 1
    else:
        errors.append("нужен спецсимвол (!@#$%^&*)")
        suggestions.append("добавьте ! или @ в конце пароля")
    
    if re.search(r'(.)\1{2,}', password):
        suggestions.append("избегайте повторяющихся символов (aaa, 111)")
    
    if re.search(r'password|123456|qwerty|admin|letmein', password.lower()):
        errors.append("пароль слишком простой и часто используется")
        suggestions.append("используйте уникальную комбинацию слов")
    
    if len(set(password)) < 5:
        suggestions.append("используйте больше разных символов")
    
    return score, errors, suggestions

def hash_password(password):
    sha256_hash = hashlib.sha256()
    sha256_hash.update(password.encode('utf-8'))
    return sha256_hash.hexdigest()

def show_strength(score):
    if score >= 5:
        return "СУПЕР СИЛЬНЫЙ", "Отлично! Пароль очень надежный."
    elif score == 4:
        return "СИЛЬНЫЙ", "Хороший пароль, можно использовать."
    elif score == 3:
        return "СРЕДНИЙ", "Пароль можно усилить."
    elif score == 2:
        return "СЛАБЫЙ", "Рекомендуется улучшить."
    else:
        return "ОЧЕНЬ СЛАБЫЙ", "Срочно смените пароль!"

def get_password():
    print("=" * 60)
    print("ПРОВЕРКА НАДЕЖНОСТИ ПАРОЛЯ")
    print("=" * 60)
    print("\nКритерии оценки:")
    print("  Длина (8+ символов)")
    print("  Заглавные и строчные буквы")
    print("  Цифры")
    print("  Специальные символы")
    print("  Длина 12+ символов (бонус)")
    print("  Уникальность символов")
    print("\n" + "=" * 60)
    
    print("\nХотите создать свой пароль или сгенерировать надежный?")
    print("1 - Ввести свой пароль")
    print("2 - Сгенерировать надежный пароль")
    
    choice = input("\nВаш выбор (1 или 2): ").strip()
    
    if choice == "2":
        print("\nГенерация надежного пароля...")
        password = generate_strong_password()
        print(f"\nСгенерированный пароль: {password}")
        return password
    else:
        try:
            password = getpass.getpass("\nВведите пароль: ")
            return password
        except:
            password = input("\nВведите пароль: ")
            return password

def main():
    password = get_password()
    
    score, errors, suggestions = check_password(password)
    
    status, message = show_strength(score)
    
    password_hash = hash_password(password)
    
    print("\n" + "=" * 60)
    print("РЕЗУЛЬТАТ ПРОВЕРКИ")
    print("=" * 60)
    
    print(f"\nПароль: {'*' * len(password)}")
    print(f"Длина: {len(password)} символов")
    print(f"Оценка: {score} из 5")
    print(f"Статус: {status}")
    print(f"Совет: {message}")
    
    if errors:
        print("\nОШИБКИ (нужно исправить):")
        for i, error in enumerate(errors, 1):
            print(f"  {i}. {error}")
    
    if suggestions:
        print("\nСОВЕТЫ ПО УЛУЧШЕНИЮ:")
        for i, suggestion in enumerate(suggestions, 1):
            print(f"  {i}. {suggestion}")
    
    print("\n" + "=" * 60)
    print("ХЭШИРОВАНИЕ ПАРОЛЯ (SHA-256)")
    print("=" * 60)
    print(f"\nХэш: {password_hash}")
    print(f"Длина хэша: {len(password_hash)} символов")
    print("\nВнимание! Хэш необратим. Пароль нельзя восстановить из хэша.")
    
    if score < 3:
        print("\nПРИМЕРЫ ХОРОШИХ ПАРОЛЕЙ:")
        print("  Пример 1: MySecureP@ssw0rd2024!")
        print("  Пример 2: Suns3t!B3ach#H0use")
        print("  Пример 3: C0ffee&Milk!Morning")
    
    print("\n" + "=" * 60)

if __name__ == "__main__":
    main()
import re
import getpass

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

def show_strength(score):
    if score >= 5:
        return "СУПЕР СИЛЬНЫЙ", "Отлично! Пароль очень надежный.", "зеленый"
    elif score == 4:
        return "СИЛЬНЫЙ", "Хороший пароль, можно использовать.", "зеленый"
    elif score == 3:
        return "СРЕДНИЙ", "Пароль можно усилить.", "желтый"
    elif score == 2:
        return "СЛАБЫЙ", "Рекомендуется улучшить.", "красный"
    else:
        return "ОЧЕНЬ СЛАБЫЙ", "Срочно смените пароль!", "красный"

def get_password():
    print("=" * 60)
    print("ПРОВЕРКА НАДЕЖНОСТИ ПАРЛЯ")
    print("=" * 60)
    print("\nКритерии оценки:")
    print("  Длина (8+ символов)")
    print("  Заглавные и строчные буквы")
    print("  Цифры")
    print("  Специальные символы")
    print("  Длина 12+ символов (бонус)")
    print("  Уникальность символов")
    print("\n" + "=" * 60)
    
    try:
        password = getpass.getpass("\nВведите пароль: ")
        return password
    except:
        password = input("\nВведите пароль: ")
        return password

def main():
    password = get_password()
    
    score, errors, suggestions = check_password(password)
    
    status, message, color = show_strength(score)
    
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
    
    if score < 3:
        print("\nПРИМЕРЫ ХОРОШИХ ПАРОЛЕЙ:")
        print("  Пример 1: MySecureP@ssw0rd2024!")
        print("  Пример 2: Suns3t!B3ach#H0use")
        print("  Пример 3: C0ffee&Milk!Morning")
    
    print("\n" + "=" * 60)

if __name__ == "__main__":
    main()
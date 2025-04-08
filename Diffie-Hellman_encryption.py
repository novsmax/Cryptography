import random

def is_prime(n, k=10):
    """
    Проверяет, является ли число простым, используя тест Миллера-Рабина.
    n - проверяемое число
    k - количество проверок (влияет на вероятность ошибки)
    """
    if n <= 1 or n == 4:
        return False
    if n <= 3:
        return True

    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1

    for _ in range(k):
        a = random.randint(2, n - 2)
        x = pow_mod(a, d, n)
        if x == 1 or x == n - 1:
            continue

        for _ in range(r - 1):
            x = pow_mod(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def pow_mod(base, exponenta, module):

    if module == 1:
        return 0

    result = 1
    base = base % module

    while exponenta > 0:
        if exponenta % 2 == 1:
            result = (result * base) % module

        exponenta = exponenta >> 1
        base = (base * base) % module

    return result

def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

def generate_prime(bits):

    while True:
        candidate = random.getrandbits(bits)
        candidate |= (1 << bits - 1) | 1

        if is_prime(candidate):
            return candidate


def generate_dh_parameters(bits=512):

    p = generate_prime(bits)
    # Для больших чисел поиск примитивного корня может быть долгим,
    # поэтому часто используют 2, 3, 5 и т.д., которые часто являются
    # примитивными корнями для многих простых чисел
    g = 2

    return p, g


def generate_keypair(p, g, bits=256):

    private_key = random.getrandbits(bits) % (p - 1) + 1
    public_key = pow_mod(g, private_key, p)

    return private_key, public_key


def compute_shared_secret(other_public_key, private_key, p):

    shared_secret = pow_mod(other_public_key, private_key, p)
    return shared_secret


def main():

    key_size = 64

    print("=== Протокол Диффи-Хеллмана ===")

    p, g = generate_dh_parameters(key_size)
    print(f"Общие параметры:")
    print(f"p = {p} (простое число)")
    print(f"g = {g} (примитивный корень по модулю p)")

    alice_private, alice_public = generate_keypair(p, g, key_size // 2)
    print(f"\nАлиса:")
    print(f"Закрытый ключ (x) = {alice_private}")
    print(f"Открытый ключ (X) = {alice_public}")

    bob_private, bob_public = generate_keypair(p, g, key_size // 2)
    print(f"\nБоб:")
    print(f"Закрытый ключ (y) = {bob_private}")
    print(f"Открытый ключ (Y) = {bob_public}")

    print("\n--- Обмен открытыми ключами ---")
    print("Алиса отправляет Бобу свой открытый ключ (X)")
    print("Боб отправляет Алисе свой открытый ключ (Y)")

    alice_shared = compute_shared_secret(bob_public, alice_private, p)
    bob_shared = compute_shared_secret(alice_public, bob_private, p)

    print("\n--- Вычисление общего секретного ключа ---")
    print(f"Алиса вычисляет: K = Y^x mod p = {bob_public}^{alice_private} mod {p} = {alice_shared}")
    print(f"Боб вычисляет: K = X^y mod p = {alice_public}^{bob_private} mod {p} = {bob_shared}")

    if alice_shared == bob_shared:
        print("\n✓Алиса и Боб получили одинаковый общий секретный ключ!")
        print(f"Общий секретный ключ: {alice_shared}")
    else:
        print("\n✗ Ошибка! Алиса и Боб получили разные ключи.")


main()
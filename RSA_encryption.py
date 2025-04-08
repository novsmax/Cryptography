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


def extended_gcd(a, b):

    if a == 0:
        return b, 0, 1
    else:
        gcd_value, x1, y1 = extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd_value, x, y


def mod_inverse(a, m):
    gcd_value, x, y = extended_gcd(a, m)
    if gcd_value != 1:
        raise Exception("Модульная инверсия не существует")
    else:
        return (x % m + m) % m

def generate_prime(bits):

    while True:
        candidate = random.getrandbits(bits)
        candidate |= (1 << bits - 1) | 1

        if is_prime(candidate):
            return candidate


def generate_RSA_key(bits=1024):

    p = generate_prime(bits // 2)
    q = generate_prime(bits // 2)

    n = p * q
    phi = (p - 1) * (q - 1)

    # e: 1 < e < φ(n) и gcd(e, φ(n)) = 1
    e = random.randint(2, phi - 1)
    while gcd(e, phi) != 1:
        e = random.randint(2, phi - 1)

    # d: (d * e) % φ(n) = 1
    d = mod_inverse(e, phi)

    public_key = (e, n)
    private_key = (d, n)

    return public_key, private_key


def encrypt(message, public_key):

    e, n = public_key
    m = text_to_int(message)
    if m >= n:
        raise ValueError("Сообщение слишком большое для данного ключа")
    # Шифруем: c = m^e mod n
    encrypted_text = pow_mod(m, e, n)

    return encrypted_text


def decrypt(text_to_decrypt, private_key):
    d, n = private_key
    m = pow_mod(text_to_decrypt, d, n)
    decrypted_text = int_to_text(m)

    return decrypted_text


def text_to_int(text):
    bytes_data = text.encode('utf-8')
    big_int = int.from_bytes(bytes_data, byteorder='big')
    return big_int


def int_to_text(big_int, byte_length=None):
    if byte_length is None:
        byte_length = (big_int.bit_length() + 7) // 8

    bytes_data = big_int.to_bytes(byte_length, byteorder='big')
    return bytes_data.decode('utf-8')



def main(key_size):
    public_key, private_key = generate_RSA_key(key_size)
    print(f"Открытый ключ (e, n): {public_key}")
    print(f"Закрытый ключ (d, n): {private_key}")

    message = "Привет, давай прогуляем пару"
    print(f"\nИсходное сообщение: {message}")

    encrypted = encrypt(message, public_key)
    print(f"Зашифрованное сообщение: {encrypted}")

    decrypted = decrypt(encrypted, private_key)
    print(f"Расшифрованное сообщение: {decrypted}")

    if message == decrypted:
        print("\nУспешно зашифровано и расшифровано.")
    else:
        print("\nОшибка! Cообщение не совпадает с исходным.")


main(1024)
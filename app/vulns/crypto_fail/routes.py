import base64
from datetime import datetime
from flask import Blueprint, render_template, request
from flask_login import login_required, current_user
from cryptography.fernet import Fernet
import bcrypt

bp_crypto = Blueprint('crypto_fail', __name__, url_prefix='/crypto_fail')

# Add more users as needed
user_data_plaintext = {
    'alice': 'secret123',
    'bob': 'passw0rd',
    'charlie': 'letmein',
    'diana': 'qwerty'
}

user_data_base64 = {
    user: base64.b64encode(pw.encode()).decode()
    for user, pw in {
        'eve': 'hunter2',
        'frank': '123456',
        'grace': 'admin1',
        'heidi': 'abc123'
    }.items()
}

def log_crypto(username, method_used, result, vuln_type="CRYPTO"):
    with open('logs/general_logs.txt', 'a') as log_file:
        log_file.write(f"\n===== {vuln_type} ATTEMPT =====\n")
        log_file.write(f"User: {username}\n")
        log_file.write(f"Time: {datetime.now()}\n")
        log_file.write(f"Used: {method_used}\n")
        log_file.write(f"Result: {result}\n")
        log_file.write("================================")

@bp_crypto.route('/', methods=['GET', 'POST'])
@login_required
def crypto_fail():
    result_plain = None
    result_b64 = None
    query_plain = None
    query_b64 = None

    if request.method == 'POST':
        method = request.form.get('method')

        if method == 'plain':
            username = request.form.get('username_plain')
            password = request.form.get('password_plain')
            user_info = user_data_plaintext.get(username)

            if user_info:
                real_pw = user_info
                query_plain = f"plaintext: {password} == {real_pw}"
                result_plain = 'success' if password == real_pw else 'fail'
            else:
                query_plain = 'User not found in database.'
                result_plain = 'fail'

            log_crypto(
                current_user.username,
                f"[plain] Username: {username}, Password: {password}, Expected: {user_info}",
                f"Plain Result: {result_plain}"
            )

        elif method == 'b64':
            username = request.form.get('username_b64')
            password = request.form.get('password_b64')
            user_info = user_data_base64.get(username)

            if user_info:
                encoded_pw = base64.b64encode(password.encode()).decode()
                query_b64 = f"base64({password}) == {user_info}"
                result_b64 = 'success' if encoded_pw == user_info else 'fail'

                log_crypto(
                    current_user.username,
                    f"[b64] Username: {username}, Password: {password}, Encoded: {encoded_pw}, Expected: {user_info}",
                    f"B64 Result: {result_b64}"
                )
            else:
                query_b64 = 'User not found in database.'
                result_b64 = 'fail'

                log_crypto(
                    current_user.username,
                    f"[b64] Username: {username}, Password: {password}, User not found.",
                    f"B64 Result: {result_b64}"
                )

    return render_template(
        'vulns/crypto_fail.html',
        result_plain=result_plain,
        result_b64=result_b64,
        query_plain=query_plain,
        query_b64=query_b64,
        user_data_plaintext=user_data_plaintext,
        user_data_base64=user_data_base64
    )

@bp_crypto.route('/fix', methods=['GET', 'POST'])
@login_required
def crypto_fail_fix():
    hashed_pw = None
    encrypted_data = None
    decrypted_data = None
    failed_decryption = None
    stored_hash = None
    verification_hash = None
    hash_result = None
    password_entered = ''
    password_attempt = ''
    key_used = ''

    if request.method == 'POST':
        method = request.form.get('method')

        if method == 'hash':
            password_entered = request.form.get('password_hash', '')
            stored_hash = bcrypt.hashpw(password_entered.encode(), bcrypt.gensalt()).decode()

            log_crypto(
                current_user.username,
                f"[hash] Stored password: {password_entered}, Hashed: {stored_hash}",
                "Saved hash for future comparison"
            )

        elif method == 'compare':
            password_attempt = request.form.get('password_compare', '')
            stored_hash = request.form.get('stored_hash', '')
            verification_hash = bcrypt.hashpw(password_attempt.encode(), bcrypt.gensalt()).decode()
            is_match = bcrypt.checkpw(password_attempt.encode(), stored_hash.encode())
            hash_result = "Match" if is_match else "No match"

            log_crypto(
                current_user.username,
                f"[compare] Attempted password: {password_attempt}, Hashed attempt: {verification_hash}, Stored hash: {stored_hash}",
                f"Comparison Result: {hash_result}"
            )

        elif method == 'encrypt':
            plaintext = request.form.get('plaintext', '')
            key = Fernet.generate_key()
            cipher_device1 = Fernet(key)

            encrypted_data = cipher_device1.encrypt(plaintext.encode()).decode()
            key_used = key.decode()

            log_crypto(
                current_user.username,
                f"[encrypt] Plaintext: {plaintext}, Key used: {key_used}",
                f"Encrypted: {encrypted_data}"
            )

        elif method == 'decrypt':
            encrypted_data = request.form.get('encrypted_data', '')
            key_used = request.form.get('key_used', '')
            try:
                cipher_device2 = Fernet(key_used.encode())
                decrypted_data = cipher_device2.decrypt(encrypted_data.encode()).decode()

                log_crypto(
                    current_user.username,
                    "[decrypt] Decryption with correct key",
                    f"Decrypted: {decrypted_data}"
                )
            except Exception as e:
                decrypted_data = None
                failed_decryption = f"Decryption failed (correct key error): {e}"

        elif method == 'decrypt_wrong':
            encrypted_data = request.form.get('encrypted_data', '')
            wrong_key = Fernet.generate_key()
            try:
                wrong_cipher = Fernet(wrong_key)
                wrong_cipher.decrypt(encrypted_data.encode()).decode()
            except Exception as e:
                failed_decryption = "Decryption failed (wrong key): " + str(e)

            log_crypto(
                current_user.username,
                "[decrypt_wrong] Attempted decryption with wrong key",
                failed_decryption
            )

    return render_template('vulns/crypto_fail_fix.html',
        stored_hash=stored_hash,
        verification_hash=verification_hash,
        password_entered=password_entered,
        password_attempt=password_attempt,
        hash_result=hash_result,
        encrypted_data=encrypted_data,
        decrypted_data=decrypted_data,
        failed_decryption=failed_decryption,
        key_used=key_used
    )


@bp_crypto.route('/summary', methods=['GET', 'POST'])
@login_required
def crypto_fail_summary():
    return render_template('vulns/crypto_fail_summary.html')

@bp_crypto.route('/quiz', methods=['GET', 'POST'])
@login_required
def quiz():
    if request.method == 'POST':
        answers = {
            'q1': request.form.get('q1'),
            'q2': request.form.get('q2'),
            'q3': request.form.get('q3'),
            'q4': request.form.get('q4'),
            'q5_1': request.form.get('q5_1'),
            'q5_2': request.form.get('q5_2'),
            'q5_3': request.form.get('q5_3')
        }

        correct = {
            'q1': 'c',  # "Passwords can be stolen and misused"
            'q2': 'b',  # "Anyone with DB access can retrieve real passwords"
            'q3': 'b',  # "It only transforms data without hiding meaning"
            'q4': 'salt',  # "salt" is the correct answer
            'q5_1': 'A',
            'q5_2': 'C',
            'q5_3': 'B'
        }

        acceptable_q4 = ['salt']

        explanations = {
            'q1': "Storing passwords in plain text exposes them to risk, as anyone who gains access to the database can steal and misuse the passwords.",
            'q2': "If passwords are stored without hashing, anyone with access to the database can retrieve the real passwords, leading to a serious security risk.",
            'q3': "Base64 is not encryption because it only transforms data and does not hide its meaning, making it easily reversible.",
            'q4': "Passwords should always be hashed with a unique salt to prevent attackers from using precomputed hash values (e.g., rainbow tables) to crack passwords.",
            'q5_1': "bcrypt and Fernet are secure methods for hashing passwords or encrypting data. They provide strong cryptographic guarantees.",
            'q5_2': "Base64 is a simple encoding, not encryption, and should not be used to protect passwords or sensitive data.",
            'q5_3': "Encryption is insufficient for password protection as it can be reversed if the key is compromised. Passwords should instead be hashed using secure hashing algorithms which are one-way and designed specifically for password storage."
        }

        wrong = {}
        score = 0

        for key, expected in correct.items():
            user_answer = (answers.get(key) or '').strip()

            # Special handling for Q4 (accepts 'salt')
            if key == 'q4':
                if user_answer.lower() in acceptable_q4:
                    score += 1
                else:
                    wrong[key] = {
                        'your_answer': user_answer or 'Blank',
                        'correct_answer': 'salt'
                    }
            else:
                if user_answer.lower() == expected.lower():
                    score += 1
                else:
                    wrong[key] = {
                        'your_answer': user_answer or 'Blank',
                        'correct_answer': expected,
                        'explanation': explanations[key]
                    }

        total = len(correct)
        passed = score >= 4  # Adjusted to 4 since the quiz has 5 questions

        # Log submission
        with open('logs/general_logs.txt', 'a') as log:
            log.write("\n===== QUIZ SUBMISSION: CRYPTO FAILURES =====\n")
            log.write(f"User: {current_user.username}\n")
            log.write(f"Time: {datetime.now()}\n")
            log.write(f"Score: {score}/{total}\n")
            for q, a in answers.items():
                log.write(f"{q}: {a}\n")
            log.write("================================")

        return render_template(
            'quiz/crypto_fail_quiz.html',
            submitted=True,
            score=score,
            total=total,
            passed=passed,
            wrong=wrong
        )
    return render_template('quiz/crypto_fail_quiz.html')

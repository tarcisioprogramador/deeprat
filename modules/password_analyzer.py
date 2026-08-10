import re
import math
from collections import Counter

class PasswordAnalyzer:
    def __init__(self):
        self.common_passwords = [
            "123456", "password", "12345678", "qwerty", "abc123",
            "monkey", "master", "dragon", "111111", "baseball",
            "iloveyou", "trustno1", "sunshine", "letmein", "welcome"
        ]
        
    def calculate_entropy(self, password):
        charset_size = 0
        if re.search(r'[a-z]', password):
            charset_size += 26
        if re.search(r'[A-Z]', password):
            charset_size += 26
        if re.search(r'[0-9]', password):
            charset_size += 10
        if re.search(r'[^a-zA-Z0-9]', password):
            charset_size += 32
        
        if charset_size == 0:
            return 0
        
        entropy = len(password) * math.log2(charset_size)
        return round(entropy, 2)
    
    def analyze_strength(self, password):
        score = 0
        feedback = []
        
        if len(password) >= 8:
            score += 1
        else:
            feedback.append("Mínimo 8 caracteres")
        
        if len(password) >= 12:
            score += 1
        
        if re.search(r'[a-z]', password) and re.search(r'[A-Z]', password):
            score += 1
        else:
            feedback.append("Use maiúsculas e minúsculas")
        
        if re.search(r'[0-9]', password):
            score += 1
        else:
            feedback.append("Adicione números")
        
        if re.search(r'[^a-zA-Z0-9]', password):
            score += 1
        else:
            feedback.append("Adicione caracteres especiais")
        
        if password.lower() in self.common_passwords:
            score = 0
            feedback.append("Senha muito comum!")
        
        entropy = self.calculate_entropy(password)
        
        if entropy < 28:
            level = "FRACA"
        elif entropy < 36:
            level = "MÉDIA"
        elif entropy < 60:
            level = "FORTE"
        else:
            level = "MUITO FORTE"
        
        return {
            "password": password[:2] + "*" * (len(password) - 2),
            "length": len(password),
            "entropy": entropy,
            "score": score,
            "max_score": 5,
            "level": level,
            "feedback": feedback,
            "char_types": {
                "lowercase": bool(re.search(r'[a-z]', password)),
                "uppercase": bool(re.search(r'[A-Z]', password)),
                "numbers": bool(re.search(r'[0-9]', password)),
                "special": bool(re.search(r'[^a-zA-Z0-9]', password))
            }
        }
    
    def generate_wordlist(self, base_word, modes=None):
        if modes is None:
            modes = ["leetspeak", "case", "append"]
        
        wordlist = set()
        wordlist.add(base_word)
        
        if "leetspeak" in modes:
            leet_map = {'a': '4', 'e': '3', 'i': '1', 'o': '0', 's': '5', 't': '7'}
            leet_word = base_word.lower()
            for char, replacement in leet_map.items():
                leet_word = leet_word.replace(char, replacement)
            wordlist.add(leet_word)
            wordlist.add(leet_word.upper())
        
        if "case" in modes:
            wordlist.add(base_word.upper())
            wordlist.add(base_word.lower())
            wordlist.add(base_word.capitalize())
            wordlist.add(base_word.swapcase())
        
        if "append" in modes:
            for i in range(10):
                wordlist.add(f"{base_word}{i}")
                wordlist.add(f"{base_word}!")
                wordlist.add(f"{base_word}@")
        
        if "reverse" in modes:
            wordlist.add(base_word[::-1])
        
        return sorted(list(wordlist))

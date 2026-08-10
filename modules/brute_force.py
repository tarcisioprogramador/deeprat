class BruteForceModule:
    def __init__(self):
        self.common_passwords = [
            "123456", "password", "12345678", "qwerty", "abc123",
            "monkey", "master", "dragon", "111111", "baseball",
            "iloveyou", "trustno1", "sunshine", "letmein", "welcome",
            "admin", "root", "toor", "pass", "test", "guest",
            "master", "changeme", "default", "secret", "password1",
            "123456789", "1234567890", "12345", "1234", "000000"
        ]
        
        self.services = {
            "ssh": {"port": 22, "tool": "hydra", "protocol": "ssh"},
            "ftp": {"port": 21, "tool": "hydra", "protocol": "ftp"},
            "http": {"port": 80, "tool": "hydra", "protocol": "http-get"},
            "https": {"port": 443, "tool": "hydra", "protocol": "https-get"},
            "mysql": {"port": 3306, "tool": "hydra", "protocol": "mysql"},
            "postgres": {"port": 5432, "tool": "hydra", "protocol": "postgres"},
            "rdp": {"port": 3389, "tool": "hydra", "protocol": "rdp"},
            "smb": {"port": 445, "tool": "hydra", "protocol": "smb"},
            "telnet": {"port": 23, "tool": "hydra", "protocol": "telnet"},
            "pop3": {"port": 110, "tool": "hydra", "protocol": "pop3"},
            "imap": {"port": 143, "tool": "hydra", "protocol": "imap"},
            "snmp": {"port": 161, "tool": "hydra", "protocol": "snmp"}
        }
        
    def generate_wordlist(self, base_words=None, modes=None):
        if base_words is None:
            base_words = ["admin", "root", "user", "test"]
        if modes is None:
            modes = ["numbers", "symbols", "years", "leetspeak"]
        
        wordlist = set()
        
        for word in base_words:
            wordlist.add(word)
            wordlist.add(word.lower())
            wordlist.add(word.upper())
            wordlist.add(word.capitalize())
            
            if "numbers" in modes:
                for i in range(10):
                    wordlist.add(f"{word}{i}")
                    wordlist.add(f"{word}{i}{i}")
                wordlist.add(f"{word}123")
                wordlist.add(f"{word}1234")
                wordlist.add(f"{word}12345")
            
            if "symbols" in modes:
                wordlist.add(f"{word}!")
                wordlist.add(f"{word}@")
                wordlist.add(f"{word}#")
                wordlist.add(f"{word}$")
                wordlist.add(f"{word}!")
                wordlist.add(f"!{word}")
                wordlist.add(f"@{word}")
            
            if "years" in modes:
                for year in range(2000, 2030):
                    wordlist.add(f"{word}{year}")
                    wordlist.add(f"{year}{word}")
            
            if "leetspeak" in modes:
                leet_map = {'a': '4', 'e': '3', 'i': '1', 'o': '0', 's': '5', 't': '7'}
                leet_word = word.lower()
                for char, replacement in leet_map.items():
                    leet_word = leet_word.replace(char, replacement)
                wordlist.add(leet_word)
                wordlist.add(leet_word.upper())
        
        for pwd in self.common_passwords:
            wordlist.add(pwd)
        
        return sorted(list(wordlist))
    
    def generate_hydra_command(self, target, service, username=None, wordlist=None, port=None):
        if service not in self.services:
            return {"error": f"Serviço não suportado: {service}"}
        
        svc_info = self.services[service]
        
        if port is None:
            port = svc_info["port"]
        
        if wordlist is None:
            wordlist = "/usr/share/wordlists/rockyou.txt"
        
        if username:
            cmd = f"hydra -l {username} -P {wordlist} {target} {svc_info['protocol']} -s {port}"
        else:
            cmd = f"hydra -L /usr/share/wordlists/users.txt -P {wordlist} {target} {svc_info['protocol']} -s {port}"
        
        return {
            "tool": "hydra",
            "command": cmd,
            "target": target,
            "service": service,
            "port": port,
            "protocol": svc_info["protocol"],
            "description": f"Força bruta em {service.upper()}://{target}:{port}",
            "tips": [
                "Use -t para ajustar threads (padrão: 16)",
                "Use -v ou -V para verbose",
                "Use -f para parar no primeiro sucesso",
                "Use -o para salvar resultados em arquivo"
            ]
        }
    
    def generate_medusa_command(self, target, service, username=None, wordlist=None, port=None):
        if service not in self.services:
            return {"error": f"Serviço não suportado: {service}"}
        
        svc_info = self.services[service]
        
        if port is None:
            port = svc_info["port"]
        
        if wordlist is None:
            wordlist = "/usr/share/wordlists/rockyou.txt"
        
        cmd = f"medusa -h {target} -u {username or 'admin'} -P {wordlist} -M {svc_info['protocol']} -n {port}"
        
        return {
            "tool": "medusa",
            "command": cmd,
            "target": target,
            "service": service,
            "port": port,
            "description": f"Força bruta medusa em {service.upper()}://{target}:{port}",
            "tips": [
                "Use -t para threads",
                "Use -f para parar no primeiro sucesso",
                "Use -O para log detalhado"
            ]
        }
    
    def generate_ncrack_command(self, target, service, username=None, wordlist=None, port=None):
        if service not in self.services:
            return {"error": f"Serviço não suportado: {service}"}
        
        svc_info = self.services[service]
        
        if port is None:
            port = svc_info["port"]
        
        if wordlist is None:
            wordlist = "/usr/share/wordlists/rockyou.txt"
        
        cmd = f"ncrack -p {port} --user {username or 'admin'} -P {wordlist} {target}:{port}"
        
        return {
            "tool": "ncrack",
            "command": cmd,
            "target": target,
            "service": service,
            "port": port,
            "description": f"Força bruta ncrack em {service.upper()}://{target}:{port}",
            "tips": [
                "Use -T para timing template (0-5)",
                "Use --connection-limit para limitar conexões",
                "Use -f para parar no primeiro sucesso"
            ]
        }
    
    def generate_hashcat_command(self, hash_type, hash_file, wordlist=None):
        hash_types = {
            "md5": "0",
            "sha1": "100",
            "sha256": "1400",
            "sha512": "1800",
            "ntlm": "1000",
            "bcrypt": "3200"
        }
        
        if hash_type not in hash_types:
            return {"error": f"Tipo de hash não suportado: {hash_type}"}
        
        if wordlist is None:
            wordlist = "/usr/share/wordlists/rockyou.txt"
        
        cmd = f"hashcat -m {hash_types[hash_type]} {hash_file} {wordlist}"
        
        return {
            "tool": "hashcat",
            "command": cmd,
            "hash_type": hash_type,
            "hash_mode": hash_types[hash_type],
            "description": f"Força bruta hash {hash_type.upper()} com hashcat",
            "tips": [
                "Use -a 0 para modo dicionário",
                "Use -a 3 para brute force",
                "Use -o para salvar resultados",
                "Use --show para ver resultados"
            ]
        }
    
    def list_services(self):
        return [
            {"name": svc, "port": info["port"], "protocol": info["protocol"]}
            for svc, info in self.services.items()
        ]

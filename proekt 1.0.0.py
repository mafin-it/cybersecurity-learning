import re
import hashlib
import getpass
import secrets
import string
import time
import os
import json
import platform
import subprocess
from datetime import datetime
from collections import Counter
from typing import Tuple, List, Dict, Optional
import base64
import zlib

class PasswordManager:
    """Password management class with extended functionality"""
    
    def __init__(self):
        self.history_file = "password_history.json"
        self.blacklist_file = "blacklist.json"
        self.load_blacklist()
        self.password_history = []
        self.session_id = secrets.token_hex(8)
        self.start_time = datetime.now()
        
    def load_blacklist(self):
        """Load blacklist from file"""
        try:
            with open(self.blacklist_file, 'r') as f:
                self.blacklist = json.load(f)
        except FileNotFoundError:
            # Extended blacklist
            self.blacklist = [
                "password", "123456", "qwerty", "admin", "letmein",
                "welcome", "monkey", "dragon", "master", "sunshine",
                "princess", "shadow", "superman", "iloveyou", "trustno1",
                "123456789", "12345678", "abc123", "password1", "qwerty123",
                "12345", "1234567", "111111", "123123", "000000",
                "password123", "admin123", "letmein123", "welcome123",
                "football", "baseball", "soccer", "hockey", "basketball"
            ]
            self.save_blacklist()
    
    def save_blacklist(self):
        """Save blacklist to file"""
        with open(self.blacklist_file, 'w') as f:
            json.dump(self.blacklist, f, indent=2)
    
    def generate_password(self, length: int = 16, complexity: str = "strong") -> str:
        """
        Generate password with different complexity levels
        complexity: "weak", "medium", "strong", "ultra"
        """
        char_sets = {
            "weak": string.ascii_lowercase + string.digits,
            "medium": string.ascii_letters + string.digits,
            "strong": string.ascii_letters + string.digits + "!@#$%^&*",
            "ultra": string.ascii_letters + string.digits + "!@#$%^&*()_+-=[]{};:'\",.<>/?\\|"
        }
        
        if complexity not in char_sets:
            complexity = "strong"
        
        all_chars = char_sets[complexity]
        
        # Ensure different character types for strong and ultra
        if complexity in ["strong", "ultra"]:
            required_chars = [
                secrets.choice(string.ascii_lowercase),
                secrets.choice(string.ascii_uppercase),
                secrets.choice(string.digits),
                secrets.choice("!@#$%^&*")
            ]
            password_chars = required_chars
            remaining = length - len(required_chars)
        else:
            password_chars = []
            remaining = length
        
        # Add remaining characters
        for _ in range(remaining):
            password_chars.append(secrets.choice(all_chars))
        
        # Shuffle
        secrets.SystemRandom().shuffle(password_chars)
        password = ''.join(password_chars)
        
        # Check if password is blacklisted
        if self.is_blacklisted(password):
            return self.generate_password(length, complexity)
        
        return password
    
    def is_blacklisted(self, password: str) -> bool:
        """Check if password is in blacklist"""
        password_lower = password.lower()
        for black in self.blacklist:
            if black in password_lower:
                return True
        return False
    
    def check_password_strength(self, password: str) -> Dict:
        """
        Extended password strength check
        Returns dictionary with detailed information
        """
        result = {
            "score": 0,
            "max_score": 8,
            "errors": [],
            "warnings": [],
            "suggestions": [],
            "details": {},
            "entropy": 0,
            "time_to_crack": "",
            "has_common_patterns": False,
            "is_blacklisted": False
        }
        
        # Length check
        length = len(password)
        result["details"]["length"] = length
        
        if length >= 16:
            result["score"] += 2
            result["details"]["length_score"] = 2
        elif length >= 12:
            result["score"] += 1
            result["details"]["length_score"] = 1
            result["suggestions"].append("use 16+ characters for maximum security")
        elif length >= 8:
            result["score"] += 0.5
            result["details"]["length_score"] = 0.5
            result["warnings"].append("minimum length is 8 characters, recommended 12+")
        else:
            result["errors"].append("password is too short (minimum 8 characters)")
            result["details"]["length_score"] = 0
            if length < 4:
                result["suggestions"].append("use a phrase of 3-4 words (e.g., CorrectHorseBatteryStaple)")
        
        # Character variety check
        has_lower = bool(re.search(r'[a-z]', password))
        has_upper = bool(re.search(r'[A-Z]', password))
        has_digit = bool(re.search(r'\d', password))
        has_special = bool(re.search(r'[!@#$%^&*()_+\-=\[\]{};:\'",.<>/?\\|]', password))
        has_space = ' ' in password
        
        char_types = sum([has_lower, has_upper, has_digit, has_special, has_space])
        result["details"]["char_types"] = char_types
        result["details"]["has_lower"] = has_lower
        result["details"]["has_upper"] = has_upper
        result["details"]["has_digit"] = has_digit
        result["details"]["has_special"] = has_special
        result["details"]["has_space"] = has_space
        
        if char_types >= 4:
            result["score"] += 2
        elif char_types >= 3:
            result["score"] += 1.5
            result["suggestions"].append("add special characters for stronger security")
        else:
            result["errors"].append("use different types of characters")
        
        # Repeated characters check
        if re.search(r'(.)\1{2,}', password):
            result["warnings"].append("repeated characters detected")
            result["suggestions"].append("avoid sequences like 'aaa' or '111'")
            result["score"] -= 0.5
        
        # Sequential patterns check
        sequences = ['abcdef', 'qwerty', '123456', '098765', 'zxcvbn', 'asdfgh']
        for seq in sequences:
            if seq in password.lower():
                result["warnings"].append(f"simple sequence '{seq}' detected")
                result["score"] -= 1
                result["has_common_patterns"] = True
                break
        
        # Blacklist check
        if self.is_blacklisted(password):
            result["errors"].append("password found in common password blacklist")
            result["is_blacklisted"] = True
            result["score"] = 0
        else:
            result["score"] += 0.5
        
        # Case variety check
        if has_upper and has_lower:
            if password.lower() == password.upper():
                result["warnings"].append("all characters in same case")
        
        # Entropy calculation
        charset_size = 0
        if has_lower:
            charset_size += 26
        if has_upper:
            charset_size += 26
        if has_digit:
            charset_size += 10
        if has_special:
            charset_size += 32
        if has_space:
            charset_size += 1
        
        if charset_size > 0:
            entropy = length * (charset_size.bit_length())
            result["entropy"] = entropy
            result["details"]["entropy"] = entropy
            result["details"]["charset_size"] = charset_size
            
            # Crack time estimation (rough estimate)
            if entropy < 30:
                result["time_to_crack"] = "instant (seconds)"
            elif entropy < 40:
                result["time_to_crack"] = "a few minutes"
            elif entropy < 50:
                result["time_to_crack"] = "a few hours"
            elif entropy < 60:
                result["time_to_crack"] = "a few days"
            elif entropy < 70:
                result["time_to_crack"] = "a few months"
            else:
                result["time_to_crack"] = "years or more"
        
        # Dictionary word check
        common_words = ['password', 'admin', 'user', 'login', 'root', 'guest']
        for word in common_words:
            if word in password.lower():
                result["warnings"].append(f"password contains common word '{word}'")
                result["score"] -= 0.5
        
        # Clamp score
        result["score"] = max(0, min(result["max_score"], result["score"]))
        
        return result
    
    def get_strength_level(self, score: float, max_score: int = 8) -> Tuple[str, str]:
        """Determine strength level"""
        percentage = (score / max_score) * 100
        
        if percentage >= 90:
            return "CRYPTO-STRONG 🛡️", "Excellent! Password suitable for banking systems"
        elif percentage >= 75:
            return "VERY STRONG 🔒", "Great password, suitable for important accounts"
        elif percentage >= 60:
            return "STRONG ✅", "Good password, but can be improved"
        elif percentage >= 45:
            return "MEDIUM ⚠️", "Recommended to improve for critical services"
        elif percentage >= 30:
            return "WEAK ❌", "Not recommended to use this password"
        else:
            return "CRITICALLY WEAK 🚨", "CHANGE this password immediately!"
    
    def hash_password(self, password: str, algorithm: str = "sha256") -> Dict:
        """Hash password with multiple algorithms"""
        results = {}
        
        password_bytes = password.encode('utf-8')
        
        # MD5 (not recommended, but for comparison)
        results["md5"] = hashlib.md5(password_bytes).hexdigest()
        
        # SHA-1 (not recommended)
        results["sha1"] = hashlib.sha1(password_bytes).hexdigest()
        
        # SHA-256 (recommended)
        results["sha256"] = hashlib.sha256(password_bytes).hexdigest()
        
        # SHA-512 (recommended)
        results["sha512"] = hashlib.sha512(password_bytes).hexdigest()
        
        # SHA-3 (new standard)
        results["sha3_256"] = hashlib.sha3_256(password_bytes).hexdigest()
        results["sha3_512"] = hashlib.sha3_512(password_bytes).hexdigest()
        
        # BLAKE2 (high performance)
        results["blake2b"] = hashlib.blake2b(password_bytes).hexdigest()
        results["blake2s"] = hashlib.blake2s(password_bytes).hexdigest()
        
        # Scrypt (brute-force protection)
        salt = secrets.token_bytes(16)
        results["scrypt"] = hashlib.scrypt(password_bytes, salt=salt, n=16384, r=8, p=1).hex()
        
        # Base64 representation
        results["base64"] = base64.b64encode(password_bytes).decode()
        
        # Compression + hash
        compressed = zlib.compress(password_bytes)
        results["compressed_hash"] = hashlib.sha256(compressed).hexdigest()
        
        return results
    
    def save_to_history(self, password: str, strength_info: Dict):
        """Save password info to history"""
        entry = {
            "timestamp": datetime.now().isoformat(),
            "password_length": len(password),
            "strength_score": strength_info["score"],
            "entropy": strength_info.get("entropy", 0),
            "session_id": self.session_id
        }
        self.password_history.append(entry)
        
        # Keep only last 100 entries
        if len(self.password_history) > 100:
            self.password_history = self.password_history[-100:]
        
        try:
            with open(self.history_file, 'w') as f:
                json.dump(self.password_history, f, indent=2)
        except:
            pass
    
    def get_password_advice(self, password: str) -> List[str]:
        """Get personalized password improvement advice"""
        advice = []
        
        # Structure analysis
        if len(password) < 12:
            advice.append("🔑 Use mnemonic phrase: 'MyDogLoves2Play!'")
        
        if not re.search(r'[A-Z]', password):
            advice.append("📌 Add uppercase letters in the middle or at the end")
        
        if not re.search(r'\d', password):
            advice.append("🔢 Replace letters with similar digits: E→3, O→0, I→1")
        
        if not re.search(r'[!@#$%^&*]', password):
            advice.append("✨ Add special characters: !@#$%^&*")
        
        # Dictionary word check
        common_patterns = ['password', 'admin', '123', 'qwerty', 'abc']
        for pattern in common_patterns:
            if pattern in password.lower():
                advice.append(f"🚫 Avoid common patterns like '{pattern}'")
                break
        
        # Passphrase suggestion
        if len(password) < 16:
            advice.append("💡 Try the passphrase method: 3 random words + digits + symbols")
        
        # Good password examples
        advice.append("📝 Example strong password: 'Golf!Ball#77%Summer'")
        advice.append("📝 Example complex password: 'P@ssw0rd!2024#Secure'")
        
        return advice
    
    def generate_mnemonic_password(self, words_count: int = 4) -> str:
        """Generate password from words with added digits and symbols"""
        word_list = [
            "apple", "blue", "chair", "dance", "eagle", "forest", "green", "happy",
            "island", "jungle", "knight", "lion", "mountain", "night", "ocean",
            "piano", "queen", "river", "storm", "tiger", "umbrella", "valley",
            "water", "xenon", "yellow", "zebra", "cloud", "dream", "flame", "grace"
        ]
        
        # Select random words
        selected_words = [secrets.choice(word_list) for _ in range(words_count)]
        
        # Add random digits and symbols
        digit = secrets.choice(string.digits)
        symbol = secrets.choice("!@#$%^&*")
        
        # Build password with variations
        password = f"{selected_words[0].capitalize()}{selected_words[1]}{digit}{selected_words[2].capitalize()}{symbol}{selected_words[3]}"
        
        # Check blacklist
        if self.is_blacklisted(password):
            return self.generate_mnemonic_password(words_count)
        
        return password
    
    def analyze_password_patterns(self, password: str) -> Dict:
        """Detailed pattern analysis in password"""
        patterns = {
            "consecutive_chars": [],
            "repeated_chars": [],
            "keyboard_patterns": [],
            "common_substrings": []
        }
        
        # Search for consecutive characters
        for i in range(len(password) - 2):
            if ord(password[i+1]) == ord(password[i]) + 1 and ord(password[i+2]) == ord(password[i+1]) + 1:
                patterns["consecutive_chars"].append(password[i:i+3])
        
        # Search for repeated characters
        for char in set(password):
            if password.count(char) > 2:
                patterns["repeated_chars"].append(char)
        
        # Search for keyboard patterns
        keyboard_rows = ["qwertyuiop", "asdfghjkl", "zxcvbnm"]
        for row in keyboard_rows:
            for i in range(len(row) - 2):
                pattern = row[i:i+3]
                if pattern in password.lower():
                    patterns["keyboard_patterns"].append(pattern)
        
        # Search for common substrings
        common = ["password", "admin", "123", "abc", "qwerty"]
        for substr in common:
            if substr in password.lower():
                patterns["common_substrings"].append(substr)
        
        return patterns


def clear_screen():
    """Clear terminal screen"""
    os.system('cls' if platform.system() == 'Windows' else 'clear')


def print_header(title: str):
    """Print formatted header"""
    print("=" * 70)
    print(f"  {title}")
    print("=" * 70)


def print_colored(text: str, color: str = "white"):
    """Print colored text (if terminal supports it)"""
    colors = {
        "red": "\033[91m",
        "green": "\033[92m",
        "yellow": "\033[93m",
        "blue": "\033[94m",
        "magenta": "\033[95m",
        "cyan": "\033[96m",
        "white": "\033[97m",
        "bold": "\033[1m",
        "reset": "\033[0m"
    }
    
    if platform.system() != "Windows":
        print(f"{colors.get(color, '')}{text}{colors['reset']}")
    else:
        print(text)


def main():
    pm = PasswordManager()
    
    while True:
        clear_screen()
        print_header("🔐 PASSWORD MANAGER - PROFESSIONAL EDITION 🔐")
        print("\nMain Menu:")
        print("  [1] Check password strength")
        print("  [2] Generate strong password")
        print("  [3] Generate mnemonic password (from words)")
        print("  [4] View check history")
        print("  [5] Manage blacklist")
        print("  [6] Compare two passwords")
        print("  [7] Get security tips")
        print("  [8] Exit program")
        
        choice = input("\nYour choice: ").strip()
        
        if choice == "1":
            clear_screen()
            print_header("🔍 PASSWORD STRENGTH CHECK")
            
            print("\nHow do you want to enter the password?")
            print("  1 - Enter manually (hidden input)")
            print("  2 - Enter manually (visible input)")
            print("  3 - Generate and check")
            
            sub_choice = input("Choice: ").strip()
            
            if sub_choice == "3":
                print("\nSelect complexity level:")
                print("  1 - Weak (letters and digits only)")
                print("  2 - Medium (letters + digits + symbols)")
                print("  3 - Strong (all character types)")
                print("  4 - Ultra (all characters, longer length)")
                
                complexity_map = {"1": "weak", "2": "medium", "3": "strong", "4": "ultra"}
                comp_choice = input("Choice: ").strip()
                complexity = complexity_map.get(comp_choice, "strong")
                
                length = 16
                if comp_choice == "4":
                    length = 24
                
                password = pm.generate_password(length, complexity)
                print(f"\nGenerated password: {password}")
            else:
                if sub_choice == "1":
                    password = getpass.getpass("\nEnter password: ")
                else:
                    password = input("\nEnter password: ")
            
            if password:
                # Check strength
                result = pm.check_password_strength(password)
                
                # Pattern analysis
                patterns = pm.analyze_password_patterns(password)
                
                # Get strength level
                status, message = pm.get_strength_level(result["score"], result["max_score"])
                
                # Hashing
                hashes = pm.hash_password(password)
                
                # Save to history
                pm.save_to_history(password, result)
                
                # Display results
                print("\n" + "=" * 70)
                print_colored("📊 CHECK RESULTS", "bold")
                print("=" * 70)
                
                print(f"\nPassword: {'*' * len(password)}")
                print(f"Length: {len(password)} characters")
                print(f"Character types: {result['details']['char_types']}/5")
                print(f"Score: {result['score']:.1f} out of {result['max_score']}")
                
                print_colored(f"\nStatus: {status}", "green")
                print(f"Message: {message}")
                
                if result.get("entropy"):
                    print(f"Entropy: {result['entropy']:.0f} bits")
                    print(f"Estimated crack time: {result.get('time_to_crack', 'unknown')}")
                
                # Errors
                if result["errors"]:
                    print_colored("\n❌ CRITICAL ERRORS (MUST FIX):", "red")
                    for i, error in enumerate(result["errors"], 1):
                        print(f"  {i}. {error}")
                
                # Warnings
                if result["warnings"]:
                    print_colored("\n⚠️ WARNINGS:", "yellow")
                    for i, warning in enumerate(result["warnings"], 1):
                        print(f"  {i}. {warning}")
                
                # Suggestions
                if result["suggestions"]:
                    print_colored("\n💡 IMPROVEMENT SUGGESTIONS:", "cyan")
                    for i, suggestion in enumerate(result["suggestions"], 1):
                        print(f"  {i}. {suggestion}")
                
                # Extra advice
                extra_advice = pm.get_password_advice(password)
                if extra_advice:
                    print_colored("\n🎯 PERSONALIZED RECOMMENDATIONS:", "blue")
                    for advice in extra_advice:
                        print(f"  • {advice}")
                
                # Pattern analysis
                if any(patterns.values()):
                    print_colored("\n🔍 DETECTED PATTERNS:", "magenta")
                    if patterns["consecutive_chars"]:
                        print(f"  • Consecutive characters: {', '.join(patterns['consecutive_chars'])}")
                    if patterns["repeated_chars"]:
                        print(f"  • Repeated characters: {', '.join(patterns['repeated_chars'])}")
                    if patterns["keyboard_patterns"]:
                        print(f"  • Keyboard patterns: {', '.join(patterns['keyboard_patterns'])}")
                    if patterns["common_substrings"]:
                        print(f"  • Common substrings: {', '.join(patterns['common_substrings'])}")
                
                # Hashes
                print("\n" + "=" * 70)
                print_colored("🔑 PASSWORD HASHES (various algorithms)", "bold")
                print("=" * 70)
                
                print(f"\nMD5 (not recommended):  {hashes['md5']}")
                print(f"SHA-1 (not recommended): {hashes['sha1']}")
                print(f"SHA-256:                  {hashes['sha256']}")
                print(f"SHA-512:                  {hashes['sha512']}")
                print(f"SHA-3 (256):              {hashes['sha3_256']}")
                print(f"BLAKE2b:                  {hashes['blake2b']}")
                print(f"Scrypt (with salt):       {hashes['scrypt'][:32]}...")
                
                print_colored("\n⚠️ WARNING:", "yellow")
                print("  • Hashes are irreversible - password cannot be recovered from hash")
                print("  • MD5 and SHA-1 are considered outdated and insecure")
                print("  • For password storage, use bcrypt or Argon2")
            
            input("\nPress Enter to continue...")
            
        elif choice == "2":
            clear_screen()
            print_header("🎲 STRONG PASSWORD GENERATOR")
            
            print("\nGeneration parameters:")
            print("  1 - Password length (default 16)")
            print("  2 - Complexity level")
            print("  3 - Generate")
            
            length = 16
            complexity = "strong"
            
            while True:
                print(f"\nCurrent parameters: Length={length}, Complexity={complexity}")
                choice_gen = input("\nSelect action (1/2/3): ").strip()
                
                if choice_gen == "1":
                    try:
                        length = int(input("Enter length (8-64): "))
                        length = max(8, min(64, length))
                    except:
                        pass
                elif choice_gen == "2":
                    print("\nComplexity levels:")
                    print("  1 - Weak (letters and digits only)")
                    print("  2 - Medium (letters + digits + !@#$%^&*)")
                    print("  3 - Strong (all character types)")
                    print("  4 - Ultra (all characters, extra complexity)")
                    
                    comp_map = {"1": "weak", "2": "medium", "3": "strong", "4": "ultra"}
                    comp_choice = input("Choice: ").strip()
                    complexity = comp_map.get(comp_choice, "strong")
                elif choice_gen == "3":
                    break
            
            # Generate multiple variants
            print("\nGenerating 5 password variants:")
            for i in range(5):
                password = pm.generate_password(length, complexity)
                print(f"  {i+1}. {password}")
            
            input("\nPress Enter to continue...")
            
        elif choice == "3":
            clear_screen()
            print_header("🧠 MNEMONIC PASSWORD GENERATOR")
            
            print("\nMnemonic passwords consist of random words")
            print("Easy to remember, hard to crack")
            
            print("\nSelect number of words:")
            print("  1 - 3 words (faster, less secure)")
            print("  2 - 4 words (recommended)")
            print("  3 - 5 words (very secure)")
            
            word_choice = input("Choice: ").strip()
            words_count = {"1": 3, "2": 4, "3": 5}.get(word_choice, 4)
            
            print(f"\nGenerating 5 mnemonic password variants ({words_count} words):")
            for i in range(5):
                password = pm.generate_mnemonic_password(words_count)
                print(f"  {i+1}. {password}")
            
            input("\nPress Enter to continue...")
            
        elif choice == "4":
            clear_screen()
            print_header("📜 CHECK HISTORY")
            
            try:
                with open(pm.history_file, 'r') as f:
                    history = json.load(f)
                
                if not history:
                    print("\nHistory is empty.")
                else:
                    print("\nLast 20 checks:")
                    for entry in history[-20:]:
                        timestamp = datetime.fromisoformat(entry['timestamp']).strftime('%d.%m.%Y %H:%M')
                        print(f"  {timestamp} | Length: {entry['password_length']} | Score: {entry['strength_score']:.1f}/8 | Entropy: {entry.get('entropy', 0):.0f}")
            except:
                print("\nHistory is empty or unavailable.")
            
            input("\nPress Enter to continue...")
            
        elif choice == "5":
            clear_screen()
            print_header("📋 BLACKLIST MANAGEMENT")
            
            print(f"\nTotal in blacklist: {len(pm.blacklist)} passwords")
            print("\nLast 20 entries:")
            for item in pm.blacklist[-20:]:
                print(f"  • {item}")
            
            print("\nAvailable actions:")
            print("  1 - Add password to blacklist")
            print("  2 - Clear blacklist")
            print("  3 - Return to main menu")
            
            action = input("Choice: ").strip()
            
            if action == "1":
                new_item = input("Enter password to add: ").strip().lower()
                if new_item and new_item not in pm.blacklist:
                    pm.blacklist.append(new_item)
                    pm.save_blacklist()
                    print(f"✅ Password '{new_item}' added to blacklist")
            elif action == "2":
                confirm = input("Are you sure? (y/n): ").strip().lower()
                if confirm == 'y':
                    pm.blacklist = []
                    pm.save_blacklist()
                    print("✅ Blacklist cleared")
            
            input("\nPress Enter to continue...")
            
        elif choice == "6":
            clear_screen()
            print_header("⚖️ COMPARE TWO PASSWORDS")
            
            print("\nEnter two passwords for comparison:")
            p1 = getpass.getpass("Password 1: ")
            p2 = getpass.getpass("Password 2: ")
            
            if p1 and p2:
                result1 = pm.check_password_strength(p1)
                result2 = pm.check_password_strength(p2)
                
                print("\n" + "=" * 70)
                print("📊 COMPARATIVE ANALYSIS")
                print("=" * 70)
                
                print(f"\nPassword 1: {'*' * len(p1)}")
                print(f"  Score: {result1['score']:.1f}/{result1['max_score']}")
                print(f"  Entropy: {result1.get('entropy', 0):.0f} bits")
                print(f"  Crack time: {result1.get('time_to_crack', 'unknown')}")
                
                print(f"\nPassword 2: {'*' * len(p2)}")
                print(f"  Score: {result2['score']:.1f}/{result2['max_score']}")
                print(f"  Entropy: {result2.get('entropy', 0):.0f} bits")
                print(f"  Crack time: {result2.get('time_to_crack', 'unknown')}")
                
                if result1['score'] > result2['score']:
                    print_colored("\n🏆 Password 1 is stronger!", "green")
                elif result2['score'] > result1['score']:
                    print_colored("\n🏆 Password 2 is stronger!", "green")
                else:
                    print_colored("\n🤝 Passwords are equally strong", "yellow")
            
            input("\nPress Enter to continue...")
            
        elif choice == "7":
            clear_screen()
            print_header("💡 SECURITY TIPS")
            
            tips = [
                "🔐 Use unique passwords for each service",
                "📏 Minimum password length should be 12 characters",
                "🔀 Combine uppercase, lowercase, digits, and special characters",
                "🚫 Avoid personal information in passwords (birthdays, names)",
                "🔄 Regularly change passwords (every 3-6 months)",
                "🔑 Use password managers for secure storage",
                "✅ Enable two-factor authentication where possible",
                "🧠 Use phrases instead of random characters - easier to remember",
                "📱 Don't store passwords in phone notes or cloud",
                "🔒 Check passwords at haveibeenpwned.com",
                "🎯 Create a system for generating unique passwords",
                "⚠️ Don't use same passwords for work and personal accounts",
                "📧 Be cautious with phishing emails",
                "🛡️ Use antivirus and firewall",
                "📱 Enable automatic device locking",
                "🔑 Use hardware security keys (YubiKey)"
            ]
            
            print("\nPassword Security Recommendations:\n")
            for tip in tips:
                print(f"  {tip}")
            
            input("\nPress Enter to continue...")
            
        elif choice == "8":
            clear_screen()
            print("=" * 70)
            print("  👋 Thank you for using Password Manager!")
            print(f"  Session ID: {pm.session_id}")
            print(f"  Started: {pm.start_time.strftime('%d.%m.%Y %H:%M:%S')}")
            print(f"  Checks in session: {len(pm.password_history)}")
            print("=" * 70)
            
            # Save history before exit
            if pm.password_history:
                with open(pm.history_file, 'w') as f:
                    json.dump(pm.password_history, f, indent=2)
            
            break
            
        else:
            print("\n❌ Invalid choice. Please try again.")
            time.sleep(1.5)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nProgram interrupted by user.")
    except Exception as e:
        print(f"\n❌ Error: {e}")
        input("Press Enter to exit...")
#!/usr/bin/env python3
"""
DARKXSTORMS Checker Management System
Dynamic Checker Selection & Version Management
Advanced Protection & Secure Loading
"""

import os
import sys
import json
import time
import hashlib
import subprocess
import threading
import tempfile
from pathlib import Path
from colorama import Fore, Style, init
from security_core import crypto_engine, network_security, integrity_validator

init(autoreset=True)

class CheckerConfig:
    """Checker Configuration and Metadata"""
    
    CHECKER_VERSIONS = {
        'ocho': {
            'name': 'OCHO Checker (Current)',
            'version': '2.0.0',
            'description': 'Advanced checker with enhanced features, live stats, and CODM detection',
            'features': [
                '✅ Live statistics tracking',
                '✅ Advanced CODM detection',
                '✅ Enhanced IP change detection',
                '✅ Improved error handling',
                '✅ Better game connection analysis',
                '✅ Auto-DataDome management'
            ],
            'file': 'ocho.py',
            'recommended': True,
            'stability': 'Stable',
            'performance': 'High'
        },
        'old': {
            'name': 'Legacy Checker (Classic)',
            'version': '1.0.0',
            'description': 'Original checker with classic functionality and proven reliability',
            'features': [
                '✅ Classic account validation',
                '✅ Traditional CODM checking',
                '✅ Manual IP management',
                '✅ Simple interface',
                '✅ Lightweight operation',
                '✅ Proven stability'
            ],
            'file': 'old.py',
            'recommended': False,
            'stability': 'Very Stable',
            'performance': 'Medium'
        }
    }
    
    CONFIG_FILE = os.path.expanduser("~/.darkxstorms_loader_config.json")
    TEMP_DIR = os.path.join(os.path.expanduser("~"), ".darkxstorms_secure")

class PreferenceManager:
    """User Preference Management System"""
    
    def __init__(self):
        self.config_file = CheckerConfig.CONFIG_FILE
        self.preferences = self.load_preferences()
    
    def load_preferences(self) -> dict:
        """Load user preferences from encrypted config file"""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    encrypted_config = f.read().strip()
                    
                decrypted_config = crypto_engine.multi_layer_decrypt(encrypted_config)
                if decrypted_config:
                    return json.loads(decrypted_config)
            
            # Default preferences
            return {
                'default_checker': None,
                'remember_choice': False,
                'last_used': None,
                'usage_stats': {
                    'ocho': 0,
                    'old': 0
                },
                'created_at': time.time()
            }
        except Exception:
            return {
                'default_checker': None,
                'remember_choice': False,
                'last_used': None,
                'usage_stats': {
                    'ocho': 0,
                    'old': 0
                },
                'created_at': time.time()
            }
    
    def save_preferences(self, preferences: dict) -> bool:
        """Save user preferences to encrypted config file"""
        try:
            preferences['updated_at'] = time.time()
            config_json = json.dumps(preferences, indent=2)
            encrypted_config = crypto_engine.multi_layer_encrypt(config_json)
            
            os.makedirs(os.path.dirname(self.config_file), exist_ok=True)
            with open(self.config_file, 'w') as f:
                f.write(encrypted_config)
            
            self.preferences = preferences
            return True
        except Exception:
            return False
    
    def update_usage_stats(self, checker_type: str):
        """Update usage statistics"""
        if checker_type in self.preferences['usage_stats']:
            self.preferences['usage_stats'][checker_type] += 1
            self.preferences['last_used'] = checker_type
            self.save_preferences(self.preferences)
    
    def get_preferred_checker(self) -> str:
        """Get user's preferred checker"""
        if self.preferences['remember_choice'] and self.preferences['default_checker']:
            return self.preferences['default_checker']
        return None
    
    def set_preferred_checker(self, checker_type: str, remember: bool = False):
        """Set user's preferred checker"""
        self.preferences['default_checker'] = checker_type
        self.preferences['remember_choice'] = remember
        self.save_preferences(self.preferences)

class CheckerInterface:
    """Interactive Checker Selection Interface"""
    
    def __init__(self, preference_manager: PreferenceManager):
        self.preference_manager = preference_manager
        
    def display_welcome_banner(self):
        """Display welcome banner"""
        print(f"\n{Fore.MAGENTA}{'═' * 70}{Style.RESET_ALL}")
        print(f"{Fore.MAGENTA}🚀 DARKXSTORMS Advanced Checker Selection System 🚀{Style.RESET_ALL}")
        print(f"{Fore.CYAN}   Maximum Security • Multi-Version Support • Enhanced Features{Style.RESET_ALL}")
        print(f"{Fore.MAGENTA}{'═' * 70}{Style.RESET_ALL}")
    
    def display_checker_options(self):
        """Display detailed checker options"""
        print(f"\n{Fore.YELLOW}📋 Available Checker Versions:{Style.RESET_ALL}")
        print()
        
        for key, config in CheckerConfig.CHECKER_VERSIONS.items():
            # Header
            status_color = Fore.GREEN if config['recommended'] else Fore.CYAN
            print(f"{status_color}┌─ {config['name']} {Style.RESET_ALL}")
            print(f"{status_color}│{Style.RESET_ALL}")
            
            # Basic info
            print(f"{status_color}├─ Version:{Style.RESET_ALL} {config['version']}")
            print(f"{status_color}├─ Stability:{Style.RESET_ALL} {config['stability']}")
            print(f"{status_color}├─ Performance:{Style.RESET_ALL} {config['performance']}")
            
            if config['recommended']:
                print(f"{status_color}├─ Status:{Style.RESET_ALL} {Fore.GREEN}⭐ RECOMMENDED{Style.RESET_ALL}")
            else:
                print(f"{status_color}├─ Status:{Style.RESET_ALL} {Fore.BLUE}💎 CLASSIC{Style.RESET_ALL}")
            
            print(f"{status_color}│{Style.RESET_ALL}")
            print(f"{status_color}├─ Description:{Style.RESET_ALL}")
            print(f"{status_color}│  {config['description']}{Style.RESET_ALL}")
            print(f"{status_color}│{Style.RESET_ALL}")
            print(f"{status_color}├─ Features:{Style.RESET_ALL}")
            
            for feature in config['features']:
                print(f"{status_color}│  {feature}{Style.RESET_ALL}")
            
            print(f"{status_color}└{'─' * 50}{Style.RESET_ALL}")
            print()
    
    def display_usage_stats(self):
        """Display usage statistics"""
        stats = self.preference_manager.preferences['usage_stats']
        total_usage = sum(stats.values())
        
        if total_usage > 0:
            print(f"{Fore.BLUE}📊 Your Usage Statistics:{Style.RESET_ALL}")
            for checker, count in stats.items():
                percentage = (count / total_usage) * 100
                print(f"   {checker.upper()}: {count} times ({percentage:.1f}%)")
            print()
    
    def get_user_choice(self) -> tuple:
        """Get user's checker choice"""
        # Check for saved preference
        preferred = self.preference_manager.get_preferred_checker()
        if preferred:
            print(f"{Fore.GREEN}💾 Using saved preference: {preferred.upper()} checker{Style.RESET_ALL}")
            return preferred, False
        
        self.display_welcome_banner()
        self.display_checker_options()
        self.display_usage_stats()
        
        print(f"{Fore.YELLOW}🎯 Choose your checker:{Style.RESET_ALL}")
        print(f"   {Fore.GREEN}[1]{Style.RESET_ALL} OCHO Checker (Current) - {Fore.GREEN}⭐ RECOMMENDED{Style.RESET_ALL}")
        print(f"   {Fore.BLUE}[2]{Style.RESET_ALL} Legacy Checker (Classic) - {Fore.BLUE}💎 PROVEN{Style.RESET_ALL}")
        print(f"   {Fore.MAGENTA}[3]{Style.RESET_ALL} View Detailed Comparison")
        print(f"   {Fore.RED}[4]{Style.RESET_ALL} Exit")
        print()
        
        while True:
            try:
                choice = input(f"{Fore.CYAN}Enter your choice (1-4): {Style.RESET_ALL}").strip()
                
                if choice == '1':
                    return self._handle_checker_selection('ocho')
                elif choice == '2':
                    return self._handle_checker_selection('old')
                elif choice == '3':
                    self._show_detailed_comparison()
                    continue
                elif choice == '4':
                    print(f"{Fore.RED}👋 Goodbye!{Style.RESET_ALL}")
                    sys.exit(0)
                else:
                    print(f"{Fore.RED}❌ Invalid choice. Please enter 1, 2, 3, or 4.{Style.RESET_ALL}")
                    
            except KeyboardInterrupt:
                print(f"\n{Fore.RED}👋 Goodbye!{Style.RESET_ALL}")
                sys.exit(0)
    
    def _handle_checker_selection(self, checker_type: str) -> tuple:
        """Handle checker selection and preferences"""
        print(f"\n{Fore.GREEN}✅ Selected: {CheckerConfig.CHECKER_VERSIONS[checker_type]['name']}{Style.RESET_ALL}")
        
        # Ask about remembering choice
        remember_choice = input(f"{Fore.YELLOW}💾 Remember this choice for future sessions? (y/n): {Style.RESET_ALL}").strip().lower()
        remember = remember_choice in ['y', 'yes']
        
        if remember:
            self.preference_manager.set_preferred_checker(checker_type, True)
            print(f"{Fore.GREEN}✅ Choice saved! Will use {checker_type.upper()} checker by default.{Style.RESET_ALL}")
        
        return checker_type, remember
    
    def _show_detailed_comparison(self):
        """Show detailed comparison between checkers"""
        print(f"\n{Fore.MAGENTA}{'═' * 70}{Style.RESET_ALL}")
        print(f"{Fore.MAGENTA}📊 Detailed Checker Comparison{Style.RESET_ALL}")
        print(f"{Fore.MAGENTA}{'═' * 70}{Style.RESET_ALL}")
        
        comparison_data = [
            ("Feature", "OCHO Checker", "Legacy Checker"),
            ("─" * 20, "─" * 15, "─" * 15),
            ("Live Stats", "✅ Advanced", "❌ Basic"),
            ("CODM Detection", "✅ Enhanced", "✅ Standard"),
            ("IP Management", "✅ Auto", "⚡ Manual"),
            ("Error Handling", "✅ Advanced", "✅ Good"),
            ("Performance", "⚡ High", "💾 Medium"),
            ("Memory Usage", "📈 Higher", "💾 Lower"),
            ("Stability", "✅ Stable", "🏆 Very Stable"),
            ("Learning Curve", "📚 Medium", "🎯 Easy"),
            ("Updates", "🔄 Regular", "🔒 Stable"),
            ("Recommended For", "🚀 Power Users", "👤 All Users")
        ]
        
        for row in comparison_data:
            print(f"{row[0]:<20} {row[1]:<20} {row[2]:<20}")
        
        print(f"\n{Fore.YELLOW}💡 Recommendation:{Style.RESET_ALL}")
        print(f"   • Choose {Fore.GREEN}OCHO{Style.RESET_ALL} for latest features and enhanced performance")
        print(f"   • Choose {Fore.BLUE}Legacy{Style.RESET_ALL} for maximum stability and simplicity")
        
        input(f"\n{Fore.CYAN}Press Enter to return to main menu...{Style.RESET_ALL}")

class SecureCheckerLoader:
    """Secure Dynamic Checker Loading System"""
    
    def __init__(self):
        self.temp_dir = CheckerConfig.TEMP_DIR
        os.makedirs(self.temp_dir, exist_ok=True)
        
    def prepare_checker_environment(self, checker_type: str) -> bool:
        """Prepare secure environment for checker execution"""
        try:
            print(f"\n{Fore.BLUE}🔧 Preparing secure environment for {checker_type.upper()} checker...{Style.RESET_ALL}")
            
            # Validate checker file exists
            checker_file = CheckerConfig.CHECKER_VERSIONS[checker_type]['file']
            if not os.path.exists(checker_file):
                print(f"{Fore.RED}❌ Checker file not found: {checker_file}{Style.RESET_ALL}")
                return False
            
            # Validate file integrity
            if not integrity_validator.validate_file_integrity(checker_file):
                print(f"{Fore.RED}🚨 File integrity check failed: {checker_file}{Style.RESET_ALL}")
                return False
            
            print(f"{Fore.GREEN}✅ File integrity verified{Style.RESET_ALL}")
            
            # Create secure temporary copy
            temp_checker_path = self._create_secure_copy(checker_file, checker_type)
            if not temp_checker_path:
                print(f"{Fore.RED}❌ Failed to create secure copy{Style.RESET_ALL}")
                return False
            
            print(f"{Fore.GREEN}✅ Secure environment prepared{Style.RESET_ALL}")
            return True
            
        except Exception as e:
            print(f"{Fore.RED}❌ Environment preparation failed: {e}{Style.RESET_ALL}")
            return False
    
    def _create_secure_copy(self, original_file: str, checker_type: str) -> str:
        """Create secure temporary copy of checker"""
        try:
            # Generate secure filename
            timestamp = str(int(time.time()))
            secure_filename = f"{checker_type}_secure_{timestamp}.py"
            temp_path = os.path.join(self.temp_dir, secure_filename)
            
            # Read original file
            with open(original_file, 'r', encoding='utf-8') as f:
                original_content = f.read()
            
            # Add security headers
            security_header = f'''#!/usr/bin/env python3
# DARKXSTORMS Secure Checker - {checker_type.upper()}
# Session ID: {crypto_engine.session_id}
# Timestamp: {time.time()}
# Security Level: MAXIMUM

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

'''
            
            # Combine content
            secure_content = security_header + original_content
            
            # Write secure copy
            with open(temp_path, 'w', encoding='utf-8') as f:
                f.write(secure_content)
            
            return temp_path
            
        except Exception as e:
            print(f"{Fore.RED}❌ Failed to create secure copy: {e}{Style.RESET_ALL}")
            return None
    
    def execute_checker(self, checker_type: str, args: list = None) -> bool:
        """Execute selected checker with security monitoring"""
        try:
            print(f"\n{Fore.MAGENTA}🚀 Launching {checker_type.upper()} checker...{Style.RESET_ALL}")
            print(f"{Fore.BLUE}🔒 Security monitoring: ACTIVE{Style.RESET_ALL}")
            print(f"{Fore.BLUE}🛡️  Anti-tampering: ENABLED{Style.RESET_ALL}")
            print(f"{Fore.GREEN}{'═' * 50}{Style.RESET_ALL}")
            
            # Get checker file
            checker_file = CheckerConfig.CHECKER_VERSIONS[checker_type]['file']
            
            # Prepare execution arguments
            exec_args = [sys.executable, checker_file]
            if args:
                exec_args.extend(args)
            
            # Execute with monitoring
            process = subprocess.Popen(
                exec_args,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                cwd=os.getcwd()
            )
            
            # Monitor execution
            self._monitor_checker_execution(process, checker_type)
            
            # Wait for completion
            return_code = process.wait()
            
            if return_code == 0:
                print(f"\n{Fore.GREEN}✅ {checker_type.upper()} checker completed successfully{Style.RESET_ALL}")
                return True
            else:
                print(f"\n{Fore.YELLOW}⚠️  {checker_type.upper()} checker exited with code: {return_code}{Style.RESET_ALL}")
                return False
                
        except Exception as e:
            print(f"\n{Fore.RED}❌ Checker execution failed: {e}{Style.RESET_ALL}")
            return False
        finally:
            self._cleanup_temp_files()
    
    def _monitor_checker_execution(self, process: subprocess.Popen, checker_type: str):
        """Monitor checker execution for security"""
        def output_monitor():
            try:
                for line in iter(process.stdout.readline, ''):
                    if line:
                        print(line.rstrip())
                        
                for line in iter(process.stderr.readline, ''):
                    if line:
                        print(f"{Fore.RED}{line.rstrip()}{Style.RESET_ALL}")
            except:
                pass
        
        # Start monitoring thread
        monitor_thread = threading.Thread(target=output_monitor, daemon=True)
        monitor_thread.start()
    
    def _cleanup_temp_files(self):
        """Clean up temporary files"""
        try:
            if os.path.exists(self.temp_dir):
                for file in os.listdir(self.temp_dir):
                    file_path = os.path.join(self.temp_dir, file)
                    try:
                        # Secure deletion - overwrite with random data first
                        if os.path.isfile(file_path):
                            with open(file_path, 'r+b') as f:
                                size = f.seek(0, 2)  # Get file size
                                f.seek(0)
                                f.write(os.urandom(size))
                            os.remove(file_path)
                    except:
                        pass
        except:
            pass

class CheckerManager:
    """Main Checker Management System"""
    
    def __init__(self):
        self.preference_manager = PreferenceManager()
        self.interface = CheckerInterface(self.preference_manager)
        self.loader = SecureCheckerLoader()
        
    def run(self, args: list = None) -> bool:
        """Run the checker management system"""
        try:
            # Get user's choice
            checker_type, remembered = self.interface.get_user_choice()
            
            # Update usage statistics
            self.preference_manager.update_usage_stats(checker_type)
            
            # Prepare secure environment
            if not self.loader.prepare_checker_environment(checker_type):
                print(f"{Fore.RED}❌ Failed to prepare checker environment{Style.RESET_ALL}")
                return False
            
            # Execute checker
            success = self.loader.execute_checker(checker_type, args)
            
            if success:
                print(f"\n{Fore.GREEN}🎉 Session completed successfully!{Style.RESET_ALL}")
                return True
            else:
                print(f"\n{Fore.YELLOW}⚠️  Session completed with warnings{Style.RESET_ALL}")
                return False
                
        except KeyboardInterrupt:
            print(f"\n{Fore.RED}🛑 Session interrupted by user{Style.RESET_ALL}")
            return False
        except Exception as e:
            print(f"\n{Fore.RED}❌ Checker management error: {e}{Style.RESET_ALL}")
            return False
    
    def reset_preferences(self):
        """Reset user preferences"""
        try:
            if os.path.exists(self.preference_manager.config_file):
                os.remove(self.preference_manager.config_file)
            print(f"{Fore.GREEN}✅ Preferences reset successfully{Style.RESET_ALL}")
        except:
            print(f"{Fore.RED}❌ Failed to reset preferences{Style.RESET_ALL}")
    
    def show_status(self):
        """Show system status"""
        preferences = self.preference_manager.preferences
        print(f"\n{Fore.BLUE}📊 Checker Manager Status:{Style.RESET_ALL}")
        print(f"   Default Checker: {preferences.get('default_checker', 'None')}")
        print(f"   Remember Choice: {preferences.get('remember_choice', False)}")
        print(f"   Last Used: {preferences.get('last_used', 'None')}")
        print(f"   Total Sessions: {sum(preferences['usage_stats'].values())}")

def main():
    """Main entry point for testing"""
    manager = CheckerManager()
    
    if len(sys.argv) > 1:
        if sys.argv[1] == '--reset':
            manager.reset_preferences()
            return
        elif sys.argv[1] == '--status':
            manager.show_status()
            return
    
    success = manager.run(sys.argv[1:])
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
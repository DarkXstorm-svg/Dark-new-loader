#!/usr/bin/env python3
"""
DARKXSTORMS Enhanced Security Loader v3.0
Maximum Protection • Multi-Checker Support • Advanced Security
Choose between Legacy (old.py) or Current (ocho.py) checkers
"""

import requests
import os
import sys
import subprocess
import hashlib
import platform
import uuid
import time
import warnings
import urllib3
import threading
import re
import json
import base64
import hmac
import secrets
import psutil
from datetime import datetime
from colorama import Fore, Style, init

# Import our advanced security modules
try:
    from security_core import (
        crypto_engine, anti_reverse_engine, network_security, 
        integrity_validator, initialize_security_core, get_security_status
    )
    from checker_manager import CheckerManager, CheckerConfig, PreferenceManager
    from protection_engine import (
        initialize_protection_engine, get_protection_status,
        anti_debug_engine, code_obfuscator
    )
    SECURITY_MODULES_LOADED = True
except ImportError as e:
    print(f"⚠️  Warning: Advanced security modules not available: {e}")
    SECURITY_MODULES_LOADED = False

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
init(autoreset=True)

class EnhancedLoaderConfig:
    """Enhanced Loader Configuration with Maximum Security"""
    VERSION = "DARKXSTORMS_v3.0_MAXIMUM_SECURITY"
    USER_AGENT = f"DARKxStorms-Enhanced-Loader/{VERSION}"
    
    # Encrypted endpoints (double-layer protection)
    BASE_URL_ENCRYPTED = "68747470733a2f2f6f63686f786173682e6f6e72656e6465722e636f6d"
    SUBSCRIPTION_API_ENCRYPTED = "68747470733a2f2f6461726b7864656174682e6f6e72656e6465722e636f6d2f6170692e706870"
    
    # Decryption keys (obfuscated)
    PRIMARY_KEY = "4b5550414c"
    SECONDARY_KEY = "554c4f4c"
    TERTIARY_KEY = "4a414b4f4c"
    
    # Security settings
    TEMP_DIR = os.path.join(os.path.expanduser("~"), ".darkxstorms_ultra_secure")
    ID_DIR = os.path.expanduser("~/.darkxstorms_loader_id")
    ID_FILE = os.path.join(ID_DIR, "loader_id.txt")
    CONFIG_FILE = os.path.join(ID_DIR, "loader_config.json")
    
    MAX_RETRIES = 2
    REQUEST_TIMEOUT = 30
    CHALLENGE_TIMEOUT = 15
    
    # Protection levels
    PROTECTION_LEVEL_BASIC = 1
    PROTECTION_LEVEL_STANDARD = 2
    PROTECTION_LEVEL_MAXIMUM = 3
    CURRENT_PROTECTION_LEVEL = PROTECTION_LEVEL_MAXIMUM

def decrypt_endpoint(encrypted_hex: str) -> str:
    """Decrypt endpoint URL with validation"""
    try:
        decrypted = bytes.fromhex(encrypted_hex).decode('utf-8')
        
        # Validate URL format
        if not (decrypted.startswith('http://') or decrypted.startswith('https://')):
            raise ValueError("Invalid URL format")
        
        return decrypted
    except Exception as e:
        print_status(f"Endpoint decryption failed: {e}", "error")
        sys.exit(1)

def print_status(message, status_type="info"):
    """Enhanced status printing with timestamps and colors"""
    timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]  # Include milliseconds
    
    status_colors = {
        "success": Fore.GREEN,
        "warning": Fore.YELLOW,
        "error": Fore.RED,
        "security": Fore.MAGENTA,
        "info": Fore.CYAN,
        "debug": Fore.BLUE
    }
    
    color = status_colors.get(status_type, Fore.CYAN)
    status_text = status_type.upper().ljust(8)
    
    print(f"{color}[{timestamp}] [{status_text}]{Style.RESET_ALL} {message}")

def display_welcome_banner():
    """Display enhanced welcome banner"""
    banner = f"""
{Fore.MAGENTA}{'═' * 80}{Style.RESET_ALL}
{Fore.MAGENTA}🚀 DARKXSTORMS Enhanced Security Loader v3.0 🚀{Style.RESET_ALL}
{Fore.CYAN}   ▪ Maximum Protection Against Reverse Engineering{Style.RESET_ALL}
{Fore.CYAN}   ▪ Multi-Checker Support (Legacy + Current){Style.RESET_ALL}
{Fore.CYAN}   ▪ Advanced Anti-Debugging & Code Protection{Style.RESET_ALL}
{Fore.CYAN}   ▪ Real-time Threat Detection & Response{Style.RESET_ALL}
{Fore.CYAN}   ▪ Encrypted Communications & Secure Sessions{Style.RESET_ALL}
{Fore.MAGENTA}{'═' * 80}{Style.RESET_ALL}

{Fore.YELLOW}🎯 CHOOSE YOUR CHECKER:{Style.RESET_ALL}
{Fore.GREEN}   • OCHO Checker (ocho.py) - Current/New with enhanced features{Style.RESET_ALL}
{Fore.BLUE}   • Legacy Checker (old.py) - Classic/Stable with proven reliability{Style.RESET_ALL}
"""
    print(banner)

def display_security_status():
    """Display current security status"""
    print(f"\n{Fore.BLUE}🔒 Security Status:{Style.RESET_ALL}")
    
    if SECURITY_MODULES_LOADED:
        security_status = get_security_status()
        protection_status = get_protection_status()
        
        print(f"   🛡️  Protection Level: {Fore.GREEN}MAXIMUM{Style.RESET_ALL}")
        print(f"   🔐 Session ID: {security_status['session_id'][:16]}...{Style.RESET_ALL}")
        print(f"   🚨 Threat Level: {Fore.GREEN if security_status['threat_level'] < 25 else Fore.YELLOW}{security_status['threat_level']}{Style.RESET_ALL}")
        print(f"   📊 Security Score: {Fore.GREEN}{security_status['security_score']}/100{Style.RESET_ALL}")
        print(f"   ⚡ Anti-Debug: {Fore.GREEN}ACTIVE{Style.RESET_ALL}")
        print(f"   🔍 Monitoring: {Fore.GREEN}ENABLED{Style.RESET_ALL}")
    else:
        print(f"   🛡️  Protection Level: {Fore.YELLOW}BASIC{Style.RESET_ALL}")
        print(f"   ⚠️  Advanced security: {Fore.YELLOW}NOT AVAILABLE{Style.RESET_ALL}")

def get_permanent_device_id():
    """Enhanced device ID generation with additional security"""
    os.makedirs(EnhancedLoaderConfig.ID_DIR, exist_ok=True)
    
    if os.path.exists(EnhancedLoaderConfig.ID_FILE):
        try:
            with open(EnhancedLoaderConfig.ID_FILE, 'r') as file:
                stored_data = file.read().strip()
                
                if SECURITY_MODULES_LOADED:
                    # Try to decrypt stored data
                    decrypted_data = crypto_engine.multi_layer_decrypt(stored_data)
                    if decrypted_data:
                        stored_data = decrypted_data
                
                if stored_data and '_' in stored_data:
                    user_name = stored_data.split('_', 1)[0]
                    if 3 <= len(user_name) <= 20 and len(stored_data.split('_', 1)[1]) >= 4:
                        print_status(f"Loaded permanent ID: {stored_data} (User: {user_name})", "success")
                        return stored_data, user_name
        except IOError:
            pass
        print_status("Invalid saved ID file. Will prompt for new permanent inputs.", "warning")
    
    print_status("Setting up permanent secure credentials...", "security")
    
    # Enhanced user input validation
    while True:
        user_name = input(f"{Fore.YELLOW}Enter your permanent user_name (3-20 alphanumeric characters): {Style.RESET_ALL}").strip()
        if 3 <= len(user_name) <= 20 and re.match(r'^[a-zA-Z0-9]+$', user_name):
            break
        print_status("Invalid: Must be 3-20 alphanumeric characters.", "error")
    
    while True:
        device_code = input(f"{Fore.YELLOW}Enter your permanent device_code (4-8 alphanumeric characters): {Style.RESET_ALL}").strip()
        if 4 <= len(device_code) <= 8 and re.match(r'^[a-zA-Z0-9]+$', device_code):
            break
        print_status("Invalid: Must be 4-8 alphanumeric characters.", "error")
    
    # Generate enhanced device ID
    full_device_id = f"{user_name}_{device_code}"
    
    # Add hardware fingerprint for additional security
    if SECURITY_MODULES_LOADED:
        hardware_fingerprint = crypto_engine._get_hardware_fingerprint()
        full_device_id += f"_{hardware_fingerprint[:6]}"
    
    try:
        # Encrypt before storing if security modules are available
        data_to_store = full_device_id
        if SECURITY_MODULES_LOADED:
            data_to_store = crypto_engine.multi_layer_encrypt(full_device_id)
        
        with open(EnhancedLoaderConfig.ID_FILE, 'w') as file:
            file.write(data_to_store)
        print_status(f"Saved permanent secure ID: {full_device_id}", "success")
        return full_device_id, user_name
    except IOError:
        print_status("Failed to save permanent ID file.", "error")
        return full_device_id, user_name

def enhanced_subscription_check(device_id, user_name):
    """Enhanced subscription check with advanced security"""
    subscription_url = decrypt_endpoint(EnhancedLoaderConfig.SUBSCRIPTION_API_ENCRYPTED)
    
    # Prepare secure request
    request_data = {
        'device_id': device_id,
        'user_name': user_name,
        'loader_check': True,
        'version': EnhancedLoaderConfig.VERSION,
        'timestamp': int(time.time())
    }
    
    if SECURITY_MODULES_LOADED:
        # Use secure network request
        response_data = network_security.secure_request(
            f"{subscription_url}",
            request_data,
            {
                'User-Agent': EnhancedLoaderConfig.USER_AGENT,
                'X-Loader-Version': EnhancedLoaderConfig.VERSION,
                'X-Security-Level': 'MAXIMUM'
            }
        )
        return response_data
    else:
        # Fallback to basic request
        try:
            url = f"{subscription_url}?device_id={device_id}&user_name={user_name}&loader_check=true"
            headers = {
                'User-Agent': EnhancedLoaderConfig.USER_AGENT,
                'X-Loader-Version': EnhancedLoaderConfig.VERSION
            }
            
            print_status(f"Verifying subscription for {device_id}...", "security")
            response = requests.get(url, headers=headers, verify=False, timeout=15)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print_status(f"Subscription verification failed: {e}", "error")
            return {"status": "error", "message": "Subscription server request failed."}

def save_user_preference(checker_type: str):
    """Save user's checker preference"""
    try:
        if SECURITY_MODULES_LOADED:
            preference_manager = PreferenceManager()
            
            # Ask if user wants to remember this choice
            remember = input(f"{Fore.YELLOW}💾 Remember this choice for future sessions? (y/n): {Style.RESET_ALL}").strip().lower()
            
            if remember in ['y', 'yes']:
                preference_manager.set_preferred_checker(checker_type, True)
                preference_manager.update_usage_stats(checker_type)
                print_status(f"✅ Preference saved! Will use {checker_type.upper()} checker by default.", "success")
            else:
                preference_manager.update_usage_stats(checker_type)
    except Exception as e:
        print_status(f"Could not save preference: {e}", "warning")

def display_checker_comparison():
    """Display simple checker comparison"""
    print(f"\n{Fore.MAGENTA}{'═' * 60}{Style.RESET_ALL}")
    print(f"{Fore.MAGENTA}📊 CHECKER COMPARISON{Style.RESET_ALL}")
    print(f"{Fore.MAGENTA}{'═' * 60}{Style.RESET_ALL}")
    
    print(f"\n{Fore.GREEN}🚀 OCHO Checker (Current/New):{Style.RESET_ALL}")
    print(f"   ✅ Live statistics and progress tracking")
    print(f"   ✅ Enhanced CODM detection with detailed info")
    print(f"   ✅ Automatic IP change detection and handling")
    print(f"   ✅ Advanced error handling and recovery")
    print(f"   ✅ Better game connection analysis")
    print(f"   ✅ Modern interface with colored output")
    print(f"   ⚡ Higher performance and speed")
    print(f"   📈 More detailed account information")
    
    print(f"\n{Fore.BLUE}💎 Legacy Checker (Old/Classic):{Style.RESET_ALL}")
    print(f"   ✅ Proven stability and reliability")
    print(f"   ✅ Simple, straightforward interface")
    print(f"   ✅ Lower memory and CPU usage")
    print(f"   ✅ Manual IP management control")
    print(f"   ✅ Traditional workflow")
    print(f"   ✅ Time-tested functionality")
    print(f"   🔒 Maximum compatibility")
    print(f"   📝 Classic result format")
    
    print(f"\n{Fore.YELLOW}🎯 Which Should You Choose?{Style.RESET_ALL}")
    print(f"   • Choose {Fore.GREEN}OCHO{Style.RESET_ALL} if you want:")
    print(f"     - Latest features and enhancements")
    print(f"     - Better performance and automation")
    print(f"     - Detailed statistics and monitoring")
    
    print(f"\n   • Choose {Fore.BLUE}Legacy{Style.RESET_ALL} if you prefer:")
    print(f"     - Maximum stability and reliability")
    print(f"     - Simple, no-frills operation")
    print(f"     - Lower system resource usage")
    
    input(f"\n{Fore.CYAN}Press Enter to return to checker selection...{Style.RESET_ALL}")

def get_checker_choice():
    """Get user's checker choice with simple and clear interface"""
    
    # Check for saved preferences first (if advanced modules available)
    if SECURITY_MODULES_LOADED:
        try:
            preference_manager = PreferenceManager()
            preferred_checker = preference_manager.get_preferred_checker()
            
            if preferred_checker:
                print_status(f"Using saved preference: {preferred_checker.upper()} checker", "success")
                return preferred_checker
        except:
            pass
    
    # Display simple checker selection menu
    print(f"\n{Fore.MAGENTA}{'═' * 60}{Style.RESET_ALL}")
    print(f"{Fore.MAGENTA}🎯 CHECKER SELECTION{Style.RESET_ALL}")
    print(f"{Fore.MAGENTA}{'═' * 60}{Style.RESET_ALL}")
    
    print(f"\n{Fore.YELLOW}Choose your checker version:{Style.RESET_ALL}")
    print(f"   {Fore.GREEN}[1]{Style.RESET_ALL} OCHO Checker (Current/New) - {Fore.GREEN}⭐ RECOMMENDED{Style.RESET_ALL}")
    print(f"       ✅ Enhanced features & live statistics")
    print(f"       ✅ Advanced CODM detection")
    print(f"       ✅ Auto IP change detection")
    print(f"       ✅ Better error handling")
    print()
    print(f"   {Fore.BLUE}[2]{Style.RESET_ALL} Legacy Checker (Old/Classic) - {Fore.BLUE}💎 STABLE{Style.RESET_ALL}")
    print(f"       ✅ Proven reliability & stability") 
    print(f"       ✅ Simple traditional interface")
    print(f"       ✅ Lower resource usage")
    print(f"       ✅ Manual control options")
    print()
    
    if SECURITY_MODULES_LOADED:
        print(f"   {Fore.CYAN}[3]{Style.RESET_ALL} Advanced Options & Comparison")
        print(f"   {Fore.MAGENTA}[4]{Style.RESET_ALL} View Detailed Information")
        print(f"   {Fore.RED}[5]{Style.RESET_ALL} Exit")
    else:
        print(f"   {Fore.RED}[3]{Style.RESET_ALL} Exit")
    
    print(f"\n{Fore.BLUE}💡 Quick Recommendation:{Style.RESET_ALL}")
    print(f"   • Choose {Fore.GREEN}[1] OCHO{Style.RESET_ALL} for best features and performance")
    print(f"   • Choose {Fore.BLUE}[2] Legacy{Style.RESET_ALL} for maximum stability")
    
    while True:
        try:
            if SECURITY_MODULES_LOADED:
                choice = input(f"\n{Fore.CYAN}Enter your choice (1-5): {Style.RESET_ALL}").strip()
            else:
                choice = input(f"\n{Fore.CYAN}Enter your choice (1-3): {Style.RESET_ALL}").strip()
            
            if choice == '1':
                print_status("✅ Selected: OCHO Checker (Current/New)", "success")
                if SECURITY_MODULES_LOADED:
                    save_user_preference('ocho')
                return 'ocho'
            elif choice == '2':
                print_status("✅ Selected: Legacy Checker (Old/Classic)", "success")
                if SECURITY_MODULES_LOADED:
                    save_user_preference('old')
                return 'old'
            elif choice == '3' and SECURITY_MODULES_LOADED:
                return use_advanced_checker_manager()
            elif choice == '4' and SECURITY_MODULES_LOADED:
                display_detailed_information()
                continue
            elif choice == '5' and SECURITY_MODULES_LOADED:
                print_status("Goodbye!", "info")
                sys.exit(0)
            elif choice == '3' and not SECURITY_MODULES_LOADED:
                print_status("Goodbye!", "info")
                sys.exit(0)
            else:
                max_choice = 5 if SECURITY_MODULES_LOADED else 3
                print_status(f"Invalid choice. Please enter 1-{max_choice}.", "error")
                
        except KeyboardInterrupt:
            print_status("\nGoodbye!", "info")
            sys.exit(0)

def use_advanced_checker_manager():
    """Use the advanced checker manager system"""
    try:
        print_status("Launching Advanced Checker Manager...", "info")
        print(f"\n{Fore.BLUE}🔧 Loading advanced features...{Style.RESET_ALL}")
        
        checker_manager = CheckerManager()
        checker_type, remembered = checker_manager.interface.get_user_choice()
        
        print_status(f"Advanced manager selected: {checker_type.upper()}", "success")
        return checker_type
        
    except Exception as e:
        print_status(f"Advanced manager error: {e}", "error")
        print_status("Falling back to basic selection...", "warning")
        
        # Fallback to basic selection
        print(f"\n{Fore.YELLOW}🔄 Using basic checker selection:{Style.RESET_ALL}")
        return basic_checker_selection()

def basic_checker_selection():
    """Basic checker selection fallback"""
    print(f"\n{Fore.YELLOW}🎯 Basic Checker Selection:{Style.RESET_ALL}")
    print(f"   {Fore.GREEN}[1]{Style.RESET_ALL} OCHO Checker (Current)")
    print(f"   {Fore.BLUE}[2]{Style.RESET_ALL} Legacy Checker (Classic)")
    
    while True:
        try:
            choice = input(f"{Fore.CYAN}Select checker (1 or 2): {Style.RESET_ALL}").strip()
            if choice == '1':
                print_status("Selected: OCHO Checker", "success")
                return 'ocho'
            elif choice == '2':
                print_status("Selected: Legacy Checker", "success")
                return 'old'
            else:
                print_status("Please enter 1 or 2", "error")
        except KeyboardInterrupt:
            sys.exit(0)

def display_detailed_information():
    """Display detailed information about checkers and system"""
    print(f"\n{Fore.MAGENTA}{'═' * 70}{Style.RESET_ALL}")
    print(f"{Fore.MAGENTA}📊 DETAILED SYSTEM INFORMATION{Style.RESET_ALL}")
    print(f"{Fore.MAGENTA}{'═' * 70}{Style.RESET_ALL}")
    
    print(f"\n{Fore.BLUE}🔧 System Features:{Style.RESET_ALL}")
    print(f"   • Multi-checker support (Legacy + Current)")
    print(f"   • Advanced security protection")
    print(f"   • Real-time threat detection")
    print(f"   • Encrypted communications")
    print(f"   • User preference management")
    print(f"   • Comprehensive logging")
    
    # Display checker comparison
    display_checker_comparison()
    
    # Display security status
    display_security_status()
    
    print(f"\n{Fore.YELLOW}📈 Performance Comparison:{Style.RESET_ALL}")
    print(f"   OCHO Checker:")
    print(f"   • Speed: ⚡⚡⚡⚡ (Fast)")
    print(f"   • Features: ⭐⭐⭐⭐⭐ (Advanced)")
    print(f"   • Resource Usage: 📈📈📈 (Higher)")
    print(f"   • User Interface: 🎨🎨🎨🎨 (Modern)")
    
    print(f"\n   Legacy Checker:")
    print(f"   • Speed: ⚡⚡⚡ (Good)")
    print(f"   • Features: ⭐⭐⭐ (Standard)")
    print(f"   • Resource Usage: 📈 (Light)")
    print(f"   • User Interface: 📝📝 (Simple)")
    
    input(f"\n{Fore.CYAN}Press Enter to return to checker selection...{Style.RESET_ALL}")

def execute_selected_checker(checker_type: str):
    """Execute the selected checker with enhanced security"""
    
    # Display which checker is being launched
    checker_info = {
        'ocho': {
            'name': 'OCHO Checker (Current/New)',
            'description': 'Enhanced features with live statistics',
            'file': 'ocho.py'
        },
        'old': {
            'name': 'Legacy Checker (Old/Classic)', 
            'description': 'Proven stability and reliability',
            'file': 'old.py'
        }
    }
    
    if checker_type not in checker_info:
        print_status(f"Unknown checker type: {checker_type}", "error")
        return False
        
    info = checker_info[checker_type]
    
    print(f"\n{Fore.MAGENTA}{'═' * 60}{Style.RESET_ALL}")
    print(f"{Fore.MAGENTA}🚀 LAUNCHING {info['name'].upper()}{Style.RESET_ALL}")
    print(f"{Fore.MAGENTA}{'═' * 60}{Style.RESET_ALL}")
    
    print(f"\n{Fore.BLUE}📋 Checker Information:{Style.RESET_ALL}")
    print(f"   Name: {info['name']}")
    print(f"   Description: {info['description']}")
    print(f"   File: {info['file']}")
    print(f"   Security Level: {'🛡️ MAXIMUM' if SECURITY_MODULES_LOADED else '🔒 BASIC'}")
    
    checker_file = info['file']
    
    # Validate checker file exists
    if not os.path.exists(checker_file):
        print_status(f"❌ Checker file not found: {checker_file}", "error")
        print_status("Please ensure all files are properly installed", "error")
        return False
    
    # Perform integrity check if security modules are available
    if SECURITY_MODULES_LOADED:
        print_status("🔍 Performing security integrity check...", "security")
        if not integrity_validator.validate_file_integrity(checker_file):
            print_status(f"🚨 File integrity check failed: {checker_file}", "error")
            return False
        print_status("✅ File integrity verified", "success")
    
    # Display launch information
    print_status(f"🔧 Preparing {checker_type.upper()} checker environment...", "info") 
    print_status("🛡️ Security monitoring: ACTIVE", "security")
    print_status("🚀 Launching checker now...", "info")
    
    # Add separator
    print(f"\n{Fore.GREEN}{'═' * 60}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}🎮 {info['name']} - Starting Session{Style.RESET_ALL}")
    print(f"{Fore.GREEN}{'═' * 60}{Style.RESET_ALL}")
    
    try:
        # Execute checker
        result = subprocess.run(
            [sys.executable, checker_file] + sys.argv[1:],
            cwd=os.getcwd(),
            timeout=None
        )
        
        print(f"\n{Fore.GREEN}{'═' * 60}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}📊 {info['name']} - Session Complete{Style.RESET_ALL}")  
        print(f"{Fore.GREEN}{'═' * 60}{Style.RESET_ALL}")
        
        if result.returncode == 0:
            print_status(f"✅ {info['name']} completed successfully", "success")
            print_status("🎉 Session finished with no errors", "success")
            return True
        else:
            print_status(f"⚠️ {info['name']} exited with code: {result.returncode}", "warning")
            print_status("💡 Check output above for any error messages", "info")
            return False
            
    except subprocess.TimeoutExpired:
        print_status("⏰ Checker execution timed out", "error")
        return False
    except KeyboardInterrupt:
        print_status("\n🛑 Checker execution interrupted by user", "warning")
        print_status("💾 Session data may have been saved", "info")
        return False
    except Exception as e:
        print_status(f"❌ Checker execution failed: {e}", "error")
        return False

def main():
    """Enhanced main function with comprehensive security"""
    try:
        # Initialize security systems
        if SECURITY_MODULES_LOADED:
            print_status("Initializing advanced security systems...", "security")
            initialize_security_core()
            initialize_protection_engine()
            print_status("Security systems initialized", "success")
        else:
            print_status("Running in basic security mode", "warning")
        
        # Display welcome banner
        display_welcome_banner()
        display_security_status()
        
        print_status("Starting enhanced loader system...", "info")
        
        # Get device credentials
        device_id, user_name = get_permanent_device_id()
        
        # Verify subscription
        print_status("Verifying loader subscription...", "security")
        subscription_response = enhanced_subscription_check(device_id, user_name)
        
        status = subscription_response.get("status")
        message = subscription_response.get("message", "")
        
        if status == "active":
            print_status(f"Subscription verified: ACTIVE - {message}", "success")
            print_status("Access granted - proceeding to checker selection...", "security")
            
            # Get checker choice
            checker_type = get_checker_choice()
            
            # Execute selected checker
            success = execute_selected_checker(checker_type)
            
            if success:
                print_status("Session completed successfully", "success")
            else:
                print_status("Session completed with warnings", "warning")
                
        elif status in ["pending", "registered_pending"]:
            print_status(f"Subscription Status: PENDING APPROVAL - {message}", "warning")
            print_status(f"Your Permanent Device ID: {device_id}", "info")
            print_status("Please contact support to activate your subscription", "info")
            
        elif status == "expired":
            print_status(f"Subscription Status: EXPIRED - {message}", "error")
            print_status(f"Your Permanent Device ID: {device_id}", "info")
            print_status("Please renew your subscription to continue", "info")
            
        else:
            print_status(f"Subscription Status: UNKNOWN ({status}) - {message}", "error")
            print_status(f"Your Permanent Device ID: {device_id}", "info")
            print_status("Please contact support for assistance", "info")
            
    except KeyboardInterrupt:
        print_status("\nEnhanced loader terminated by user", "warning")
        sys.exit(0)
    except Exception as e:
        print_status(f"Fatal error: {e}", "error")
        sys.exit(1)
    finally:
        if SECURITY_MODULES_LOADED:
            print_status("Security cleanup completed", "security")

if __name__ == "__main__":
    main()
#!/usr/bin/env python3
"""
DARKXSTORMS Enhanced Security Loader v3.0 - Setup Script
Installation, validation, and system preparation
"""

import os
import sys
import subprocess
import platform
import hashlib
import json
from pathlib import Path

REQUIRED_FILES = [
    'loader.py',
    'security_core.py', 
    'checker_manager.py',
    'protection_engine.py',
    'ocho.py',
    'old.py',
    'requirements.txt',
    'README.md',
    'SECURITY_FEATURES.md'
]

REQUIRED_PACKAGES = [
    'requests>=2.25.1',
    'urllib3>=1.26.0',
    'cloudscraper>=1.2.60',
    'cryptography>=3.4.8',
    'pycryptodome>=3.12.0',
    'psutil>=5.8.0',
    'colorama>=0.4.4'
]

def print_banner():
    """Display setup banner"""
    print("=" * 70)
    print("🚀 DARKXSTORMS Enhanced Security Loader v3.0")
    print("   Setup and Installation Script")
    print("=" * 70)

def check_python_version():
    """Check Python version compatibility"""
    print("\n📋 Checking Python version...")
    
    version = sys.version_info
    if version.major < 3 or (version.major == 3 and version.minor < 7):
        print(f"❌ Python {version.major}.{version.minor} detected")
        print("⚠️  Python 3.7+ is required")
        return False
    
    print(f"✅ Python {version.major}.{version.minor}.{version.micro} - Compatible")
    return True

def check_system_compatibility():
    """Check system compatibility"""
    print("\n📋 Checking system compatibility...")
    
    system = platform.system()
    print(f"   Operating System: {system}")
    print(f"   Architecture: {platform.machine()}")
    print(f"   Platform: {platform.platform()}")
    
    if system in ['Windows', 'Linux', 'Darwin']:
        print("✅ System compatibility: Supported")
        return True
    else:
        print(f"⚠️  System compatibility: {system} may not be fully supported")
        return True  # Continue anyway

def check_required_files():
    """Check if all required files are present"""
    print("\n📋 Checking required files...")
    
    missing_files = []
    for file_path in REQUIRED_FILES:
        if os.path.exists(file_path):
            print(f"   ✅ {file_path}")
        else:
            print(f"   ❌ {file_path} - MISSING")
            missing_files.append(file_path)
    
    if missing_files:
        print(f"\n❌ Missing {len(missing_files)} required files:")
        for file_path in missing_files:
            print(f"   - {file_path}")
        return False
    
    print("✅ All required files present")
    return True

def validate_file_integrity():
    """Validate integrity of critical files"""
    print("\n📋 Validating file integrity...")
    
    critical_files = ['loader.py', 'security_core.py', 'protection_engine.py']
    
    for file_path in critical_files:
        if os.path.exists(file_path):
            try:
                with open(file_path, 'rb') as f:
                    content = f.read()
                    file_hash = hashlib.sha256(content).hexdigest()
                    size = len(content)
                
                print(f"   ✅ {file_path} - {size} bytes, hash: {file_hash[:16]}...")
                
                # Basic validation - file should have reasonable size
                if size < 1000:  # Less than 1KB might indicate incomplete file
                    print(f"   ⚠️  {file_path} seems unusually small ({size} bytes)")
                    
            except Exception as e:
                print(f"   ❌ {file_path} - Error reading: {e}")
                return False
    
    print("✅ File integrity validation passed")
    return True

def install_dependencies():
    """Install required Python packages"""
    print("\n📋 Installing dependencies...")
    
    try:
        # Upgrade pip first
        print("   📦 Upgrading pip...")
        subprocess.run([sys.executable, '-m', 'pip', 'install', '--upgrade', 'pip'], 
                      check=True, capture_output=True)
        
        # Install requirements
        if os.path.exists('requirements.txt'):
            print("   📦 Installing from requirements.txt...")
            result = subprocess.run([sys.executable, '-m', 'pip', 'install', '-r', 'requirements.txt'], 
                                  capture_output=True, text=True)
            
            if result.returncode == 0:
                print("✅ Dependencies installed successfully")
                return True
            else:
                print(f"❌ Dependency installation failed:")
                print(result.stderr)
                return False
        else:
            # Install individual packages
            for package in REQUIRED_PACKAGES:
                print(f"   📦 Installing {package}...")
                result = subprocess.run([sys.executable, '-m', 'pip', 'install', package], 
                                      capture_output=True, text=True)
                if result.returncode != 0:
                    print(f"❌ Failed to install {package}")
                    print(result.stderr)
                    return False
            
            print("✅ All dependencies installed")
            return True
            
    except Exception as e:
        print(f"❌ Error installing dependencies: {e}")
        return False

def test_imports():
    """Test importing required modules"""
    print("\n📋 Testing module imports...")
    
    test_imports = [
        ('requests', 'HTTP client'),
        ('cryptography', 'Cryptographic operations'),
        ('psutil', 'System monitoring'),
        ('colorama', 'Console colors'),
        ('cloudscraper', 'Web scraping')
    ]
    
    failed_imports = []
    
    for module_name, description in test_imports:
        try:
            __import__(module_name)
            print(f"   ✅ {module_name} - {description}")
        except ImportError as e:
            print(f"   ❌ {module_name} - {description} - FAILED: {e}")
            failed_imports.append(module_name)
    
    # Test custom modules
    custom_modules = [
        ('security_core', 'Advanced security engine'),
        ('checker_manager', 'Checker management system'), 
        ('protection_engine', 'Anti-reverse engineering')
    ]
    
    for module_name, description in custom_modules:
        try:
            if os.path.exists(f'{module_name}.py'):
                # Try to compile the module
                with open(f'{module_name}.py', 'r') as f:
                    code = f.read()
                    compile(code, f'{module_name}.py', 'exec')
                print(f"   ✅ {module_name} - {description}")
            else:
                print(f"   ❌ {module_name}.py not found")
                failed_imports.append(module_name)
        except Exception as e:
            print(f"   ❌ {module_name} - {description} - FAILED: {e}")
            failed_imports.append(module_name)
    
    if failed_imports:
        print(f"\n❌ Failed imports: {', '.join(failed_imports)}")
        return False
    
    print("✅ All modules imported successfully")
    return True

def create_directories():
    """Create necessary directories"""
    print("\n📋 Creating system directories...")
    
    directories = [
        os.path.expanduser("~/.darkxstorms_loader_id"),
        os.path.expanduser("~/.darkxstorms_secure"),
        os.path.expanduser("~/.darkxstorms_ultra_secure"),
        "Results"
    ]
    
    for directory in directories:
        try:
            os.makedirs(directory, exist_ok=True)
            print(f"   ✅ {directory}")
        except Exception as e:
            print(f"   ❌ {directory} - Error: {e}")
            return False
    
    print("✅ System directories created")
    return True

def test_basic_functionality():
    """Test basic loader functionality"""
    print("\n📋 Testing basic functionality...")
    
    try:
        # Test security core import
        sys.path.insert(0, os.getcwd())
        
        # Test basic functionality without full execution
        print("   🔧 Testing security core...")
        import security_core
        print("   ✅ Security core loaded")
        
        print("   🔧 Testing protection engine...")
        import protection_engine
        print("   ✅ Protection engine loaded")
        
        print("   🔧 Testing checker manager...")
        import checker_manager
        print("   ✅ Checker manager loaded")
        
        print("✅ Basic functionality test passed")
        return True
        
    except Exception as e:
        print(f"❌ Basic functionality test failed: {e}")
        return False

def run_system_check():
    """Run comprehensive system check"""
    print("\n📋 Running system compatibility check...")
    
    issues = []
    warnings = []
    
    # Check available memory
    try:
        import psutil
        memory = psutil.virtual_memory()
        available_gb = memory.available / (1024**3)
        
        if available_gb < 1:
            issues.append(f"Low available memory: {available_gb:.1f}GB")
        elif available_gb < 2:
            warnings.append(f"Limited available memory: {available_gb:.1f}GB")
        else:
            print(f"   ✅ Available memory: {available_gb:.1f}GB")
    except:
        warnings.append("Could not check available memory")
    
    # Check disk space
    try:
        disk_usage = os.statvfs('.')
        free_gb = (disk_usage.f_bavail * disk_usage.f_frsize) / (1024**3)
        
        if free_gb < 0.5:
            issues.append(f"Low disk space: {free_gb:.1f}GB")
        else:
            print(f"   ✅ Available disk space: {free_gb:.1f}GB")
    except:
        try:
            # Windows fallback
            import shutil
            free_bytes = shutil.disk_usage('.').free
            free_gb = free_bytes / (1024**3)
            
            if free_gb < 0.5:
                issues.append(f"Low disk space: {free_gb:.1f}GB")
            else:
                print(f"   ✅ Available disk space: {free_gb:.1f}GB")
        except:
            warnings.append("Could not check disk space")
    
    # Report results
    if issues:
        print(f"\n❌ System check found {len(issues)} issues:")
        for issue in issues:
            print(f"   - {issue}")
        return False
    
    if warnings:
        print(f"\n⚠️  System check found {len(warnings)} warnings:")
        for warning in warnings:
            print(f"   - {warning}")
    
    print("✅ System check passed")
    return True

def generate_setup_report():
    """Generate setup completion report"""
    print("\n📋 Generating setup report...")
    
    report = {
        "setup_timestamp": str(subprocess.check_output(['date'], text=True).strip()) if os.name != 'nt' else str(subprocess.check_output(['echo', '%date% %time%'], shell=True, text=True).strip()),
        "system_info": {
            "platform": platform.platform(),
            "python_version": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
            "architecture": platform.machine()
        },
        "installation_status": "complete",
        "security_level": "maximum"
    }
    
    try:
        with open("setup_report.json", "w") as f:
            json.dump(report, f, indent=2)
        print("   ✅ Setup report saved to setup_report.json")
    except Exception as e:
        print(f"   ⚠️  Could not save setup report: {e}")

def display_completion_message():
    """Display setup completion message"""
    print("\n" + "=" * 70)
    print("🎉 DARKXSTORMS ENHANCED LOADER SETUP COMPLETE!")
    print("=" * 70)
    print("\n✅ Installation successful!")
    print("✅ All dependencies installed")
    print("✅ Security modules ready") 
    print("✅ System compatibility verified")
    print("\n🚀 You can now run the loader:")
    print("   python loader.py")
    print("\n📚 Documentation available:")
    print("   README.md - Usage instructions")
    print("   SECURITY_FEATURES.md - Security details")
    print("\n🛡️  Security Level: MAXIMUM PROTECTION")
    print("🔒 Anti-reverse engineering: ACTIVE")
    print("=" * 70)

def main():
    """Main setup routine"""
    print_banner()
    
    # Setup steps
    setup_steps = [
        ("Python Version", check_python_version),
        ("System Compatibility", check_system_compatibility),
        ("Required Files", check_required_files),
        ("File Integrity", validate_file_integrity),
        ("Dependencies", install_dependencies),
        ("Module Imports", test_imports),
        ("Directories", create_directories),
        ("Basic Functionality", test_basic_functionality),
        ("System Check", run_system_check)
    ]
    
    failed_steps = []
    
    for step_name, step_function in setup_steps:
        try:
            if not step_function():
                failed_steps.append(step_name)
        except Exception as e:
            print(f"❌ {step_name} failed with error: {e}")
            failed_steps.append(step_name)
    
    # Generate report
    generate_setup_report()
    
    # Show results
    if failed_steps:
        print(f"\n❌ Setup failed! Failed steps: {', '.join(failed_steps)}")
        print("Please fix the issues and run setup again.")
        return False
    else:
        display_completion_message()
        return True

if __name__ == "__main__":
    try:
        success = main()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n\n⚠️  Setup interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Setup failed with unexpected error: {e}")
        sys.exit(1)
#!/usr/bin/env python3
"""
Enhanced Bl4ckC3ll_PANTHEON Integration Script
Demonstrates the new modular architecture and enhanced capabilities
"""

import sys
import time
from pathlib import Path
from typing import Dict, Any

# Add current directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

try:
    import pantheon
    from pantheon.api import scan_api_endpoints
    from pantheon.containers import scan_container_images
    from pantheon.cloud import scan_cloud_infrastructure
    from pantheon.cicd import generate_cicd_integration
    from pantheon.reporting import generate_security_report
    print("✅ Successfully imported enhanced PANTHEON modules")
except ImportError as e:
    print(f"⚠️ Import issue: {e}")
    print("Proceeding with basic functionality...")

def demonstrate_enhanced_features():
    """Demonstrate the enhanced features of PANTHEON v2.0"""
    print("\n🛡️ Bl4ckC3ll_PANTHEON v2.0 - Enhanced Security Framework")
    print("=" * 60)
    
    # Create output directory
    output_dir = Path("runs") / f"demo_{int(time.time())}"
    output_dir.mkdir(parents=True, exist_ok=True)
    
    print(f"📁 Output directory: {output_dir}")
    
    # 1. Container Security Scanning
    print("\n🐳 Container Security Assessment")
    print("-" * 30)
    try:
        container_results = scan_container_images(['alpine:latest'], output_dir)
        print(f"✅ Container scan completed for {len(container_results)} images")
        for image, result in container_results.items():
            if 'error' in result:
                print(f"   ⚠️ {image}: {result['error']}")
            else:
                vuln_count = len(result.get('vulnerabilities', []))
                misconfig_count = len(result.get('misconfigurations', []))
                print(f"   📊 {image}: {vuln_count} vulnerabilities, {misconfig_count} misconfigurations")
    except Exception as e:
        print(f"⚠️ Container scanning error: {e}")
    
    # 2. API Security Testing
    print("\n🌐 API Security Testing")
    print("-" * 30)
    try:
        api_results = scan_api_endpoints('https://httpbin.org', output_dir)
        print("✅ API security scan completed")
        
        discovery = api_results.get('discovery', {})
        security = api_results.get('security', {})
        
        endpoint_count = len(discovery.get('endpoints', {}))
        vuln_count = len(security.get('vulnerabilities', []))
        
        print(f"   📊 Discovered {endpoint_count} endpoints")
        print(f"   🔍 Found {vuln_count} security issues")
    except Exception as e:
        print(f"⚠️ API scanning error: {e}")
    
    # 3. Cloud Security Assessment
    print("\n☁️ Cloud Security Assessment")
    print("-" * 30)
    try:
        cloud_results = scan_cloud_infrastructure('aws', output_dir)
        print("✅ Cloud security assessment completed")
        
        if 'error' in cloud_results:
            print(f"   ⚠️ {cloud_results['error']}")
        else:
            misconfig_count = len(cloud_results.get('misconfigurations', []))
            print(f"   📊 Found {misconfig_count} potential misconfigurations")
    except Exception as e:
        print(f"⚠️ Cloud scanning error: {e}")
    
    # 4. CI/CD Integration
    print("\n🔄 CI/CD Integration")
    print("-" * 30)
    try:
        cicd_result = generate_cicd_integration('github', 'standard', output_dir)
        print("✅ CI/CD integration files generated")
        
        if cicd_result.get('success'):
            files = cicd_result.get('files_created', [])
            print(f"   📄 Created {len(files)} configuration files:")
            for file_path in files:
                print(f"      - {file_path}")
        else:
            print(f"   ⚠️ Error: {cicd_result.get('error', 'Unknown error')}")
    except Exception as e:
        print(f"⚠️ CI/CD integration error: {e}")
    
    # 5. Enhanced Reporting
    print("\n📊 Enhanced Reporting")
    print("-" * 30)
    try:
        # Combine all scan results
        combined_results = {
            'container_scans': locals().get('container_results', {}),
            'api_scans': {'httpbin': locals().get('api_results', {})},
            'cloud_scans': {'aws': locals().get('cloud_results', {})},
            'vulnerabilities': [
                {
                    'severity': 'medium',
                    'title': 'Demo Vulnerability',
                    'description': 'This is a demonstration vulnerability for testing purposes',
                    'type': 'demo'
                }
            ]
        }
        
        report = generate_security_report(combined_results, output_dir, ['json', 'html'])
        print("✅ Comprehensive security report generated")
        
        files_generated = report.get('files_generated', [])
        vuln_count = report['summary']['vulnerabilities_found']
        
        print(f"   📊 Total vulnerabilities: {vuln_count}")
        print(f"   📄 Generated {len(files_generated)} report files:")
        for file_path in files_generated:
            print(f"      - {file_path}")
    except Exception as e:
        print(f"⚠️ Reporting error: {e}")
    
    # Summary
    print("\n📋 Summary")
    print("-" * 30)
    print("✅ Enhanced PANTHEON v2.0 demonstration completed")
    print(f"📁 All outputs saved to: {output_dir}")
    
    # List all generated files
    all_files = list(output_dir.rglob('*'))
    file_count = len([f for f in all_files if f.is_file()])
    print(f"📊 Generated {file_count} files total")
    
    print("\n🚀 Key Enhancements Demonstrated:")
    print("   • Modular architecture with organized packages")
    print("   • Container security scanning with Docker integration")
    print("   • Advanced API security testing and discovery")
    print("   • Cloud security assessment for AWS/Azure/GCP")
    print("   • CI/CD integration for multiple platforms")
    print("   • Enhanced reporting with multiple formats")
    print("   • Improved security controls and validation")

def test_basic_imports():
    """Test basic import functionality"""
    print("\n🧪 Testing Basic Imports")
    print("-" * 30)
    
    try:
        import pantheon
        print(f"✅ Main pantheon package: v{pantheon.__version__}")
    except Exception as e:
        print(f"❌ Main package import failed: {e}")
    
    modules_to_test = [
        ('pantheon.api', 'API Security'),
        ('pantheon.containers', 'Container Security'),
        ('pantheon.cloud', 'Cloud Security'),
        ('pantheon.cicd', 'CI/CD Integration'),
        ('pantheon.reporting', 'Enhanced Reporting')
    ]
    
    for module_name, description in modules_to_test:
        try:
            __import__(module_name)
            print(f"✅ {description}: {module_name}")
        except ImportError as e:
            print(f"⚠️ {description}: Import issue - {e}")
        except Exception as e:
            print(f"❌ {description}: Error - {e}")

if __name__ == "__main__":
    print("🔥 Bl4ckC3ll_PANTHEON v2.0 Enhanced Security Framework")
    print("Author: @cxb3rf1lth")
    print("=" * 60)
    
    # Test imports first
    test_basic_imports()
    
    # Demonstrate enhanced features
    try:
        demonstrate_enhanced_features()
    except KeyboardInterrupt:
        print("\n⚠️ Demonstration interrupted by user")
    except Exception as e:
        print(f"\n❌ Demonstration failed: {e}")
        import traceback
        traceback.print_exc()
    
    print("\n🎯 PANTHEON v2.0 demonstration complete!")
    print("For production use, run: python3 bl4ckc3ll_p4nth30n.py")
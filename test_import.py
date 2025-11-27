#!/usr/bin/env python3
"""Test imports for NET-WRANGLER v3.0"""

import traceback
import sys
import warnings

# Suppress numpy warnings on Windows
warnings.filterwarnings('ignore')

print("Testing imports...")

try:
    print("\n1. Testing enterprise_features...")
    from enterprise_features import (
        CloudStorageAuditor,
        SubdomainEnumerator,
        WAFDetector,
        AnomalyDetector,
        FutureSecurityFeatures
    )
    print("   ✓ Enterprise features imported successfully")
except Exception as e:
    print(f"   ✗ Enterprise features import failed:")
    traceback.print_exc()
    sys.exit(1)

try:
    print("\n2. Testing net_wrangler_v3...")
    from net_wrangler_v3 import NetWranglerV3, Config
    print("   ✓ NET-WRANGLER v3 imported successfully")
except Exception as e:
    print(f"   ✗ NET-WRANGLER v3 import failed:")
    traceback.print_exc()
    sys.exit(1)

try:
    print("\n3. Creating NetWranglerV3 instance...")
    nw = NetWranglerV3()
    print(f"   ✓ Instance created successfully")
    print(f"   Local IP: {nw.get_local_ip()}")
except Exception as e:
    print(f"   ✗ Failed to create instance:")
    traceback.print_exc()
    sys.exit(1)

print("\n✓ All imports successful!")

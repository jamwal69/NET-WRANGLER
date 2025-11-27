import sys
import traceback
import warnings
import os

# Suppress all warnings
warnings.filterwarnings('ignore')
os.environ['PYTHONWARNINGS'] = 'ignore'

print("Testing enterprise_features import...")

try:
    from enterprise_features import CloudStorageAuditor
    print("SUCCESS: CloudStorageAuditor imported")
except Exception as e:
    print(f"FAILED: {e}")
    traceback.print_exc()
    sys.exit(1)

try:
    from enterprise_features import FutureSecurityFeatures
    print("SUCCESS: FutureSecurityFeatures imported")
except Exception as e:
    print(f"FAILED: {e}")
    traceback.print_exc()
    sys.exit(1)

print("\n✓ All imports successful!")

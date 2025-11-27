# Encoding fix script
with open('enterprise_features.py', 'r', encoding='utf-8', errors='ignore') as f:
    content = f.read()

# Replace any problematic characters
content = content.encode('ascii', 'ignore').decode('ascii')

with open('enterprise_features_fixed.py', 'w', encoding='utf-8') as f:
    f.write(content)

print("Fixed file created: enterprise_features_fixed.py")

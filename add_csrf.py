import os
import re

# List of HTML files to update
html_files = [
    'templates/login.html',
    'templates/signup.html',
    'templates/profile.html',
    'templates/file_scanner.html',
    'templates/password_tools.html',
    'templates/security_audit.html',
    'templates/encrypted_vault.html',
]

csrf_token = '    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>'

for file_path in html_files:
    if not os.path.exists(file_path):
        print(f"❌ File not found: {file_path}")
        continue
    
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Add CSRF token after <form> tags that don't already have it
    def add_csrf_after_form(match):
        form_tag = match.group(0)
        # Check if csrf_token already exists in the next 100 characters
        next_chars = content[match.end():match.end()+200]
        if 'csrf_token' in next_chars:
            return form_tag  # Already has CSRF token
        return form_tag + '\n' + csrf_token
    
    # Find all <form> tags
    updated_content = re.sub(
        r'<form[^>]*>',
        add_csrf_after_form,
        content
    )
    
    # Write back
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(updated_content)
    
    print(f"✅ Updated: {file_path}")

print("\n🎉 All forms updated with CSRF tokens!")

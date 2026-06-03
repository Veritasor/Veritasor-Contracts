import os
import glob
import re

def fix_submit_attestation(content):
    # Regex to find client.submit_attestation calls and capture everything up to the version argument
    # then replace the last 3 arguments (proof, expiry, deprecated) with (fee, proof, expiry)
    
    # Simple replace for multiline &None, &None, &0u64
    content = content.replace(
        "        &None,\n        &None,\n        &0u64,\n",
        "        &0i128,\n        &None,\n        &None,\n"
    )
    content = content.replace(
        "        &None,\n        &None,\n        &0u64\n",
        "        &0i128,\n        &None,\n        &None\n"
    )
    # Simple replace for single line
    content = content.replace("&None, &None, &0u64", "&0i128, &None, &None")
    
    # Also fix some events_test.rs calls that accidentally have 9 arguments now
    # because of partial manual edits
    content = content.replace(
        "        &0i128,\n        &None,\n        &None,\n        &0u64,\n",
        "        &0i128,\n        &None,\n        &None,\n"
    )

    # Some tests might pass Some for expiry or proof, so let's do a more generic regex for 8 arguments
    # where the last is &0u64 or 0u64
    # find: &1u32, \n <arg1>, \n <arg2>, \n &0u64
    pattern = re.compile(r'(&[a-zA-Z0-9_]+,?\s+)(&?None|&?Some\([^)]+\)),\s+(&?None|&?Some\([^)]+\)),\s+&?0u64(,|(?=\s*\)))')
    content = pattern.sub(r'\g<1>&0i128, \g<2>, \g<3>\g<4>', content)
    
    # Also handle active_submission_test where we might have a loop or variable version
    pattern2 = re.compile(r'(&?[a-zA-Z0-9_]+,?\s+)(&?None|&?Some\([^)]+\)),\s+(&?None|&?Some\([^)]+\)),\s+&?0u64(,|(?=\s*\)))')
    content = pattern2.sub(r'\g<1>&0i128, \g<2>, \g<3>\g<4>', content)
    
    return content

if __name__ == "__main__":
    count = 0
    for filepath in glob.glob('contracts/attestation/src/**/*.rs', recursive=True):
        with open(filepath, 'r') as f:
            old_content = f.read()
            
        new_content = fix_submit_attestation(old_content)
        
        # specific unused variables fixes
        if 'expiry_test.rs' in filepath:
            new_content = new_content.replace('let challenger =', 'let _challenger =')
        if 'property_test.rs' in filepath:
            new_content = new_content.replace('let admin = client.get_admin();', 'let _admin = client.get_admin();')
        if 'dynamic_fees_test.rs' in filepath:
            new_content = new_content.replace('let business = Address::generate(&t.env);', 'let _business = Address::generate(&t.env);')
            
        if old_content != new_content:
            with open(filepath, 'w') as f:
                f.write(new_content)
            count += 1
            print(f"Fixed {filepath}")
            
    print(f"Fixed {count} files")

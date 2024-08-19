import os

def generate_file(file_path, num_rows):
    with open(file_path, 'w') as file:
        for i in range(num_rows):
            file.write(f"Row {i + 1}\n")

# Paths for test files
test_files = {
    
    'file_10000.txt': 10000,
    'file_500000.txt': 500000,
    'file_1000000.txt': 1000000,
    
}

# Directory where files will be generated
" You can use; output_dir = 'tests/test_files' "
output_dir = 'path/to/test_files' 

# Create the directory if it doesn't exist
os.makedirs(output_dir, exist_ok=True)

# Generate files
for file_name, num_rows in test_files.items():
    file_path = os.path.join(output_dir, file_name)
    generate_file(file_path, num_rows)
    print(f"Generated file: {file_path} with {num_rows} rows")

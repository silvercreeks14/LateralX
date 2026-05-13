import csv

input_file = r'C:\Users\ahsam\Desktop\Test\FIP-main2\test_set.csv'
output_file = r'C:\Users\ahsam\Desktop\Test\FIP-main2\test_set_trimmed.csv'
limit = 10000

print(f"Reading {input_file}...")
try:
    with open(input_file, 'r', encoding='utf-8', errors='ignore') as fin:
        reader = csv.reader(fin)
        header = next(reader)
        
        with open(output_file, 'w', encoding='utf-8', newline='') as fout:
            writer = csv.writer(fout)
            writer.writerow(header)
            
            count = 0
            for row in reader:
                writer.writerow(row)
                count += 1
                if count >= limit:
                    break
    
    print(f"Successfully created {output_file} with {count} events.")
except Exception as e:
    print(f"Error: {e}")

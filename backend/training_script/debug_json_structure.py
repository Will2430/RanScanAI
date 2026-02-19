import json
import pprint

# Check benign.json structure
print("="*60)
print("Checking benign.json structure")
print("="*60)

with open(r'C:\Users\willi\Downloads\archive\data\Processed\benign.json', 'r') as f:
    data = json.load(f)

print(f"Type of data: {type(data)}")

if isinstance(data, list):
    print(f"Length: {len(data)}")
    print(f"Type of first element: {type(data[0])}")
    print("\nFirst element:")
    pprint.pprint(data[0])
    if len(data) > 1:
        print("\nSecond element:")
        pprint.pprint(data[1])
elif isinstance(data, dict):
    print(f"Number of keys: {len(data)}")
    print(f"Keys: {list(data.keys())}")
    print("\nFull structure:")
    for key in data.keys():
        print(f"\nKey '{key}':")
        print(f"  Type: {type(data[key])}")
        if isinstance(data[key], list):
            print(f"  Length: {len(data[key])}")
            if len(data[key]) > 0:
                print(f"  First element type: {type(data[key][0])}")
                print(f"  First element: {data[key][0]}")
                if len(data[key]) > 1:
                    print(f"  Second element: {data[key][1]}")
        else:
            print(f"  Value: {data[key]}")
else:
    print(f"Unexpected type: {type(data)}")
    print(data)

import json
import sys
import hashlib

# import bencodepy - available if you need it!
# import requests - available if you need it!

# Examples:
#
# - decode_bencode(b"5:hello") -> b"hello"
# - decode_bencode(b"10:hello12345") -> b"hello12345"
def decode_bencode(bencoded_value):
    value, _ = decode_bencode_recursive(bencoded_value)
    return value

def decode_bencode_recursive(bencoded_value):
    if chr(bencoded_value[0]).isdigit():
        first_colon_index = bencoded_value.find(b":")
        if first_colon_index == -1:
            raise ValueError("Invalid encoded value")
        length = int(bencoded_value[:first_colon_index])
        start_index = first_colon_index + 1
        end_index = start_index + length
        if end_index > len(bencoded_value):
             raise ValueError("String length mismatch")
        return bencoded_value[start_index:end_index], bencoded_value[end_index:]
    
    elif bencoded_value[0:1] == b"i":
        end_index = bencoded_value.find(b"e")
        if end_index == -1:
            raise ValueError("Invalid encoded value")
        return int(bencoded_value[1:end_index]), bencoded_value[end_index+1:]
    
    elif bencoded_value[0:1] == b"l":
        result_list = []
        rest = bencoded_value[1:]
        while rest and rest[0:1] != b"e":
            value, rest = decode_bencode_recursive(rest)
            result_list.append(value)
        if not rest:
             raise ValueError("Invalid encoded value: unterminated list")
        return result_list, rest[1:]

    elif bencoded_value[0:1] == b"d":
        result_dict = {}
        rest = bencoded_value[1:]
        while rest and rest[0:1] != b"e":
            key, rest = decode_bencode_recursive(rest)
            if not isinstance(key, bytes):
                raise ValueError("Dictionary key must be a string")
            key = key.decode() # JSON keys must be strings
            value, rest = decode_bencode_recursive(rest)
            result_dict[key] = value
        if not rest:
            raise ValueError("Invalid encoded value: unterminated dictionary")
        return result_dict, rest[1:]

    else:
        raise NotImplementedError("Only strings, integers, lists, and dictionaries are supported at the moment")

def encode_bencode(data):
    if isinstance(data, int):
        return f"i{data}e".encode()
    elif isinstance(data, str):
        encoded = data.encode()
        return f"{len(encoded)}:".encode() + encoded
    elif isinstance(data, bytes):
        return f"{len(data)}:".encode() + b":" + data
    elif isinstance(data, list):
        return b"l" + b"".join(encode_bencode(item) for item in data) + b"e"
    elif isinstance(data, dict):
        encoded_items = []
        for key in sorted(data.keys()):
             encoded_key = encode_bencode(key)
             encoded_val = encode_bencode(data[key])
             encoded_items.append(encoded_key + encoded_val)
        return b"d" + b"".join(encoded_items) + b"e"
    else:
        raise TypeError(f"Type not serializable: {type(data)}")


def main():
    command = sys.argv[1]

    # You can use print statements as follows for debugging, they'll be visible when running tests.
    print("Logs from your program will appear here!", file=sys.stderr)

    if command == "decode":
        bencoded_value = sys.argv[2].encode()

        # json.dumps() can't handle bytes, but bencoded "strings" need to be
        # bytestrings since they might contain non utf-8 characters.
        #
        # Let's convert them to strings for printing to the console.
        def bytes_to_str(data):
            if isinstance(data, bytes):
                return data.decode()

            raise TypeError(f"Type not serializable: {type(data)}")

        # TODO: Uncomment the code below to pass the first stage
        print(json.dumps(decode_bencode(bencoded_value), default=bytes_to_str))
    elif command == "info":
        file_path = sys.argv[2]
        with open(file_path, "rb") as f:
            bencoded_content = f.read()
        
        torrent_info = decode_bencode(bencoded_content)
        print(f"Tracker URL: {torrent_info['announce'].decode()}")
        print(f"Length: {torrent_info['info']['length']}")

        info_bencoded = encode_bencode(torrent_info['info'])
        info_hash = hashlib.sha1(info_bencoded).hexdigest()
        print(f"Info Hash: {info_hash}")
    else:
        raise NotImplementedError(f"Unknown command {command}")


if __name__ == "__main__":
    main()

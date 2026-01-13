import json
import sys
import hashlib
import requests
import struct
import socket

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

def find_value_end(data, start_idx):
    char = data[start_idx:start_idx+1]
    
    if chr(data[start_idx]).isdigit():
        colon_idx = data.find(b':', start_idx)
        length = int(data[start_idx:colon_idx])
        return colon_idx + 1 + length
    
    elif char == b'i':
        end_idx = data.find(b'e', start_idx)
        return end_idx + 1
    
    elif char == b'l' or char == b'd':
        idx = start_idx + 1
        while idx < len(data):
            if data[idx:idx+1] == b'e':
                return idx + 1
            idx = find_value_end(data, idx)
        raise ValueError("Unterminated list or dictionary")
    
    else:
        raise ValueError(f"Unknown start character: {char}")

def extract_info_bytes(bencoded_data):
    # Assume the root is a dictionary
    if bencoded_data[0:1] != b'd':
        raise ValueError("Invalid torrent file: root is not a dictionary")
    
    idx = 1
    while idx < len(bencoded_data):
        if bencoded_data[idx:idx+1] == b'e':
            break
        
        # Parse Key (must be string)
        if not chr(bencoded_data[idx]).isdigit():
             raise ValueError("Dictionary keys must be strings")
        
        colon_idx = bencoded_data.find(b':', idx)
        key_len = int(bencoded_data[idx:colon_idx])
        key_start = colon_idx + 1
        key_end = key_start + key_len
        key = bencoded_data[key_start:key_end]
        
        # Move past key
        idx = key_end
        
        # Now we are at the value
        value_start = idx
        value_end = find_value_end(bencoded_data, value_start)
        
        if key == b'info':
            return bencoded_data[value_start:value_end]
        
        idx = value_end
        
    raise ValueError("Info key not found")


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

        info_bytes = extract_info_bytes(bencoded_content)
        info_hash = hashlib.sha1(info_bytes).hexdigest()
        print(f"Info Hash: {info_hash}")

        print(f"Piece Length: {torrent_info['info']['piece length']}")
        print("Piece Hashes:")
        pieces = torrent_info['info']['pieces']
        for i in range(0, len(pieces), 20):
            print(pieces[i:i+20].hex())
    elif command == "peers":
        file_path = sys.argv[2]
        with open(file_path, "rb") as f:
            bencoded_content = f.read()
        
        torrent_info = decode_bencode(bencoded_content)
        tracker_url = torrent_info['announce'].decode()
        info_bytes = extract_info_bytes(bencoded_content)
        info_hash = hashlib.sha1(info_bytes).digest()
        
        params = {
            "info_hash": info_hash,
            "peer_id": "00112233445566778899",
            "port": 6881,
            "uploaded": 0,
            "downloaded": 0,
            "left": torrent_info['info']['length'],
            "compact": 1
        }
        
        response = requests.get(tracker_url, params=params)
        decoded_response = decode_bencode(response.content)
        # print(f"Decoded response keys: {decoded_response.keys()}", file=sys.stderr)
        if 'failure reason' in decoded_response:
             raise Exception(f"Tracker failed: {decoded_response['failure reason'].decode()}")
        peers_binary = decoded_response['peers']
        
        for i in range(0, len(peers_binary), 6):
            peer = peers_binary[i:i+6]
            ip = ".".join(str(b) for b in peer[:4])
            port = struct.unpack("!H", peer[4:])[0]
            print(f"{ip}:{port}")
    elif command == "handshake":
        file_path = sys.argv[2]
        peer_address = sys.argv[3]
        peer_ip, peer_port = peer_address.split(":")
        peer_port = int(peer_port)

        with open(file_path, "rb") as f:
            bencoded_content = f.read()

        info_bytes = extract_info_bytes(bencoded_content)
        info_hash = hashlib.sha1(info_bytes).digest()
        peer_id = b"00112233445566778899" # 20 bytes

        # Construct handshake message
        protocol_len = 19
        protocol_string = b"BitTorrent protocol"
        reserved_bytes = b"\x00" * 8
        handshake_msg = bytes([protocol_len]) + protocol_string + reserved_bytes + info_hash + peer_id

        # Connect to peer
        with socket.create_connection((peer_ip, peer_port)) as s:
            s.sendall(handshake_msg)
            
            # Receive handshake response
            # Response length should be 1 byte (len) + 19 bytes (protocol) + 8 bytes (reserved) + 20 bytes (info hash) + 20 bytes (peer id) = 68 bytes
            response = s.recv(68)
            
            if len(response) < 68:
                raise Exception("Invalid handshake response length")
            
            received_peer_id = response[48:]
            print(f"Peer ID: {received_peer_id.hex()}")

    else:
        raise NotImplementedError(f"Unknown command {command}")


if __name__ == "__main__":
    main()

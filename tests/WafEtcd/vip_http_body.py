"""Bounded HTTP/1.1 JSON request decoder for disposable VIP HTTPS peers."""
import json
import re


def read_json_body(headers, stream, limit=4096):
    """Support .NET JsonContent's chunked framing without trusting lengths."""
    transfer = headers.get_all("Transfer-Encoding", [])
    lengths = headers.get_all("Content-Length", [])
    def exact(n):
        data = stream.read(n)
        if len(data) != n:
            raise ValueError("Truncated body")
        return data
    if transfer:
        if len(transfer) != 1 or transfer[0].strip().lower() != "chunked" or lengths:
            raise ValueError("Ambiguous or unsupported framing")
        data = bytearray()
        # Bound both decoded payload and framing overhead. JsonContent emits
        # plain hexadecimal chunk sizes and no trailers.
        for _ in range(256):
            line = stream.readline(64)
            if not re.fullmatch(rb"[0-9a-fA-F]{1,8}\r\n", line):
                raise ValueError("Invalid chunk header")
            n = int(line[:-2], 16)
            if n == 0:
                if exact(2) != b"\r\n":
                    raise ValueError("Unexpected trailers")
                break
            if len(data) + n > limit:
                raise ValueError("Oversize body")
            data.extend(exact(n))
            if exact(2) != b"\r\n":
                raise ValueError("Invalid chunk ending")
        else:
            raise ValueError("Excessive chunk count")
    else:
        if len(lengths) != 1 or not re.fullmatch(r"[0-9]{1,8}", lengths[0]):
            raise ValueError("Missing or invalid content length")
        n = int(lengths[0])
        if n > limit:
            raise ValueError("Oversize body")
        data = exact(n)
    result = json.loads(data)
    if not isinstance(result, dict):
        raise ValueError("JSON object required")
    return result

def decode_payload(raw_bytes):
    """Try to decode raw bytes into readable text"""
    if not raw_bytes:
        return ""
    try:
        text = raw_bytes.decode("utf-8")
        return "".join(c if c.isprintable() or c in "\n\r\t" else "." for c in text)
    except:
        return raw_bytes.hex()

def extract_http(raw_bytes):
    """Try to extract HTTP request/response text"""
    try:
        text = raw_bytes.decode("utf-8", errors="ignore")
        methods = ("GET ", "POST ", "PUT ", "DELETE ", "PATCH ", "HEAD ", "OPTIONS ")
        if text.startswith(methods) or text.startswith("HTTP/"):
            return text
    except:
        pass
    return None   
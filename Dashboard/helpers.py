from urllib.parse import urlparse

def normalize_url(url):
    """
    Normalize a URL by:
      - Converting the scheme and hostname to lowercase.
      - Removing trailing slashes from the path.
    """
    parsed = urlparse(url)
    normalized = f"{parsed.scheme.lower()}://{parsed.netloc.lower()}{parsed.path.rstrip('/')}"
    return normalized

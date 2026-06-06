from typing import Tuple, Optional
import tldextract

def levenshtein_distance(s1: str, s2: str) -> int:
    """
    Computes the Levenshtein distance between two strings.
    Used to detect domain similarity for typosquatting detection.
    """
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)

    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]

def detect_typosquatting(query_domain: str, brand_list: list) -> Tuple[bool, Optional[str]]:
    """
    Checks if query_domain is a typosquat of any brand in the brand_list.
    Returns (is_typosquat, typosquat_target).
    """
    if not query_domain:
        return False, None

    # Extract SLD (e.g. "google" from "google.com")
    extracted_query = tldextract.extract(query_domain.lower())
    query_sld = extracted_query.domain
    query_tld = extracted_query.suffix
    
    if not query_sld:
        return False, None

    # Full domain reconstruction
    query_full = f"{query_sld}.{query_tld}"

    for brand in brand_list:
        extracted_brand = tldextract.extract(brand.lower())
        brand_sld = extracted_brand.domain
        
        # If they are exactly the same, it's legitimate
        if query_sld == brand_sld:
            return False, None
            
        # Check Levenshtein distance between SLDs
        dist = levenshtein_distance(query_sld, brand_sld)
        
        # Thresholds:
        # 1. Distance of 1 or 2 edits (character replacement, deletion, insertion, or transposition)
        # 2. Minimum length of brand SLD > 3 to avoid false positives (like 'abc' -> 'abd')
        # 3. Check for specific common substitutions (e.g., '0' for 'o', '1' for 'i', 'l' for '1', etc.)
        is_substitute = False
        if len(brand_sld) > 3:
            # Check for character swaps like o/0, i/1, l/1, vv/w
            normalized_query = query_sld.replace("0", "o").replace("1", "i").replace("l", "i").replace("vv", "w")
            normalized_brand = brand_sld.replace("0", "o").replace("1", "i").replace("l", "i").replace("vv", "w")
            if normalized_query == normalized_brand:
                is_substitute = True

            if dist in [1, 2] or is_substitute:
                # Extra guard: if the query is a completely different TLD but very close, or same TLD
                # Phishing domains often use different TLDs (e.g. micros0ft.xyz)
                return True, brand

    return False, None
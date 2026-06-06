import re
from utils.entropy import calculate_entropy
from typing import Tuple

def calculate_dga_score(domain_name: str) -> Tuple[bool, float]:
    """
    Heuristic-based DGA (Domain Generation Algorithm) detection model.
    Analyzes character distribution, vowels, consonants, digits, and entropy.
    Returns (is_dga, confidence_score).
    """
    if not domain_name:
        return False, 0.0
    
    # Strip TLD and get only the domain name (SLD)
    parts = domain_name.lower().split('.')
    if len(parts) > 1:
        # Get the second-level domain (SLD)
        sld = parts[-2]
    else:
        sld = parts[0]
        
    length = len(sld)
    if length < 4:
        return False, 0.0  # Too short for DGA analysis
        
    # Calculate components
    entropy = calculate_entropy(sld)
    
    # 1. Vowels vs Consonants ratio
    vowels = set("aeiouy")
    vowels_count = sum(1 for c in sld if c in vowels)
    consonants_count = sum(1 for c in sld if c.isalpha() and c not in vowels)
    
    vowel_ratio = vowels_count / length if length > 0 else 0.0
    
    # 2. Consecutive consonants and vowels
    # Find the maximum length of consecutive consonants
    consecutive_consonants = max([len(g) for g in re.findall(r'[bcdfghjklmnpqrstvwxz]+', sld)] or [0])
    consecutive_vowels = max([len(g) for g in re.findall(r'[aeiouy]+', sld)] or [0])
    
    # 3. Digit ratio
    digits_count = sum(1 for c in sld if c.isdigit())
    digit_ratio = digits_count / length
    
    # 4. Scoring Heuristic (0.0 to 1.0)
    score = 0.0
    
    # Entropy contribution (standard domain entropy ranges from 2.0 to 4.5)
    # Entropy above 3.5 is suspicious; above 4.0 is highly suspicious
    if entropy > 4.0:
        score += 0.35
    elif entropy > 3.5:
        score += 0.20
    elif entropy > 3.0:
        score += 0.10
        
    # Consecutive consonants contribution (e.g. "qwrts" -> highly abnormal)
    if consecutive_consonants >= 5:
        score += 0.30
    elif consecutive_consonants >= 4:
        score += 0.15
    elif consecutive_consonants == 3:
        score += 0.05
        
    # Digits mixed in domain name (common in DGAs like "qwe921x")
    if digit_ratio > 0.3:
        score += 0.20
    elif digit_ratio > 0.1:
        score += 0.10
        
    # Vowel ratio anomalies (too low or too high indicates gibberish)
    if vowel_ratio < 0.2 or vowel_ratio > 0.7:
        score += 0.15
    elif vowel_ratio < 0.3:
        score += 0.05
        
    # Length multiplier (longer random domains are easier to identify and more suspicious)
    if length > 12:
        score += 0.10
    elif length < 6:
        score -= 0.10  # Smaller domains are naturally more prone to false alarms
        
    # Normalize score between 0.0 and 1.0
    score = max(0.0, min(1.0, round(score, 3)))
    
    # DGA classification threshold
    is_dga = score >= 0.65
    
    return is_dga, score
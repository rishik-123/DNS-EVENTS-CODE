import math

def calculate_entropy(s: str) -> float:
    """
    Calculates Shannon entropy of a string.
    High entropy (> 3.5) suggests random/generated data (DGA/Tunneling).
    Low entropy (< 2.5) suggests normal or patterned data.
    """
    if not s:
        return 0.0
    
    # Calculate frequency of each character
    char_counts = {}
    for char in s:
        char_counts[char] = char_counts.get(char, 0) + 1
        
    # Calculate entropy
    entropy = 0.0
    string_length = len(s)
    for count in char_counts.values():
        probability = count / string_length
        entropy -= probability * math.log2(probability)
        
    return entropy

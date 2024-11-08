import nltk
import string
from nltk.tokenize import word_tokenize
from nltk.corpus import stopwords
from nltk.stem import WordNetLemmatizer
from collections import Counter

# Download required NLTK data
nltk.download('punkt')
nltk.download('stopwords')
nltk.download('wordnet')
nltk.download('averaged_perceptron_tagger')

def process_text_file(file_path):
    """
    Process a text file to extract tokens and keywords.
    
    Args:
        file_path (str): Path to the text file
        
    Returns:
        tuple: (list of tokens, dict of keywords with frequencies)
    """
    # Read the file
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            text = file.read()
    except Exception as e:
        print(f"Error reading file: {e}")
        return [], {}
    
    # Convert to lowercase
    text = text.lower()
    
    # Remove punctuation
    text = text.translate(str.maketrans('', '', string.punctuation))
    
    # Tokenize
    tokens = word_tokenize(text)
    
    # Remove stopwords
    stop_words = set(stopwords.words('english'))
    tokens = [token for token in tokens if token not in stop_words]
    
    # Lemmatize
    lemmatizer = WordNetLemmatizer()
    tokens = [lemmatizer.lemmatize(token) for token in tokens]
    
    # Get keyword frequencies
    keyword_freq = Counter(tokens)
    
    return tokens, dict(keyword_freq.most_common())

def analyze_text(file_path):
    """
    Analyze text and print detailed statistics.
    
    Args:
        file_path (str): Path to the text file
    """
    tokens, keywords = process_text_file(file_path)
    
    print(f"\nText Analysis Results:")
    print(f"Total tokens: {len(tokens)}")
    print(f"Unique tokens: {len(set(tokens))}")
    print("\nTop 10 keywords and their frequencies:")
    for word, freq in list(keywords.items())[:]:
        print(f"{word}: {freq}")

# Example usage
if __name__ == "__main__":
    # Replace with your text file path
    file_path = "para.txt"
    analyze_text(file_path)
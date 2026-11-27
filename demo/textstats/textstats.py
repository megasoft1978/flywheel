"""Small text statistics helpers."""


def word_count(text):
    """Number of words in text; any run of whitespace separates words."""
    return len(text.split(" "))


def top_words(text, n):
    """The n most frequent words, most frequent first, ties alphabetical."""
    counts = {}
    for word in text.lower().split():
        counts[word] = counts.get(word, 0) + 1
    return sorted(counts, key=counts.get)[:n]

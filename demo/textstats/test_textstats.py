import unittest

from textstats import top_words, word_count


class TextStatsTest(unittest.TestCase):
    def test_word_count_runs_of_whitespace(self):
        self.assertEqual(word_count("hello   world\n"), 2)

    def test_word_count_empty(self):
        self.assertEqual(word_count(""), 0)

    def test_top_words_most_frequent_first(self):
        self.assertEqual(top_words("b a b c b a", 2), ["b", "a"])

    def test_top_words_ties_alphabetical(self):
        self.assertEqual(top_words("y x", 2), ["x", "y"])


if __name__ == "__main__":
    unittest.main()

"""Public prompts and examples. Test cases and fixture solutions live separately."""
from dataclasses import dataclass


@dataclass(frozen=True)
class Task:
    id: str
    signature: str
    prompt: str
    examples: tuple


SPECS = [
    ("slugify", "text", "Lowercase and join whitespace-separated words with hyphens.", ("Hello World", "hello-world")),
    ("is_balanced", "text", "Check balanced parentheses, ignoring other characters.", ("(x)", True)),
    ("rle_encode", "text", "Return a list of (character, consecutive count) pairs.", ("aab", [("a", 2), ("b", 1)])),
    ("median_of_three", "a, b, c", "Return the middle of three numbers.", ((3, 1, 2), 2)),
    ("reverse_words", "text", "Reverse whitespace-separated words, joined by one space.", ("a b", "b a")),
    ("unique_sorted", "values", "Return sorted distinct values.", ([2, 1, 2], [1, 2])),
    ("factorial", "n", "Return n factorial for nonnegative integers.", (3, 6)),
    ("fibonacci", "n", "Return Fibonacci n with F0=0 and F1=1.", (6, 8)),
    ("gcd", "a, b", "Return the nonnegative greatest common divisor.", ((12, 8), 4)),
    ("is_prime", "n", "Return whether n is a prime integer.", (7, True)),
    ("palindrome", "text", "Check exact, case-sensitive palindrome equality.", ("aba", True)),
    ("count_vowels", "text", "Count ASCII vowels, ignoring case.", ("Hello", 2)),
    ("flatten", "values", "Flatten a list of lists by one level.", ([[1], [2]], [1, 2])),
    ("chunk", "values, size", "Split into lists of positive size, retaining the remainder.", (([1, 2, 3], 2), [[1, 2], [3]])),
    ("rotate_left", "values, k", "Rotate a list left by k, including negative k.", (([1, 2, 3], 1), [2, 3, 1])),
    ("clamp", "x, low, high", "Clamp x between low and high.", ((5, 0, 3), 3)),
    ("digit_sum", "n", "Sum decimal digits of the absolute integer.", (-123, 6)),
    ("binary_string", "n", "Return binary digits for a nonnegative integer without a prefix.", (5, "101")),
    ("title_words", "text", "Capitalize whitespace-separated words and join with single spaces.", ("hello WORLD", "Hello World")),
    ("anagram", "a, b", "Check exact character multiset equality.", (("ab", "ba"), True)),
    ("second_largest", "values", "Return second-largest distinct value or None.", ([3, 1, 2], 2)),
    ("prefix_sums", "values", "Return cumulative sums, one per input value.", ([1, 2], [1, 3])),
    ("product", "values", "Return product; empty product is 1.", ([2, 3], 6)),
    ("intersection", "a, b", "Return sorted distinct intersection.", (([1, 2], [2, 3]), [2])),
    ("merge_sorted", "a, b", "Merge sorted lists, preserving duplicates.", (([1, 3], [2]), [1, 2, 3])),
    ("is_sorted", "values", "Check nondecreasing order.", ([1, 1, 2], True)),
    ("longest_word", "text", "Return first longest whitespace word, or empty string.", ("a bee cat", "bee")),
    ("count_words", "text", "Count whitespace-separated words.", ("a b", 2)),
    ("strip_punctuation", "text", "Remove ASCII punctuation characters.", ("hi!", "hi")),
    ("caesar", "text, k", "Rotate ASCII letters by k preserving case; leave others.", (("Az!", 1), "Ba!")),
    ("hamming", "a, b", "Count unequal positions in two equal-length strings.", (("abc", "axc"), 1)),
    ("two_sum", "values, target", "Return first (i,j) with i<j and target sum in nested-loop order, or None.", (([2, 7], 9), (0, 1))),
    ("dedupe", "values", "Remove duplicates while preserving first occurrences.", ([2, 1, 2], [2, 1])),
    ("frequency", "values", "Return a frequency dictionary of hashable values.", (["a", "a"], {"a": 2})),
    ("transpose", "rows", "Transpose rectangular rows into lists; empty input yields [].", ([[1, 2], [3, 4]], [[1, 3], [2, 4]])),
    ("diagonal_sum", "rows", "Sum the main diagonal of a square matrix.", ([[1, 2], [3, 4]], 5)),
    ("leap_year", "year", "Check the Gregorian leap-year rule.", (2000, True)),
    ("days_in_month", "year, month", "Return days in a valid Gregorian month.", ((2024, 2), 29)),
    ("camel_to_snake", "text", "Insert underscore before each uppercase character except at start; lowercase all.", ("helloWorld", "hello_world")),
    ("common_prefix", "words", "Return longest shared prefix, empty for no words.", (["flower", "flow"], "flow")),
    ("balanced_brackets", "text", "Check balanced (), [] and {}, ignoring other characters.", ("{[]}", True)),
    ("missing_number", "values", "Find the missing integer in 0..len(values), with distinct inputs.", ([0, 2], 1)),
    ("even_values", "values", "Return even integers in input order.", ([1, 2, 4], [2, 4])),
    ("ceil_div", "a, b", "Return mathematical ceiling of a/b for integer a and positive b.", ((5, 2), 3)),
    ("is_power_of_two", "n", "Check positive powers of two, including 1.", (8, True)),
    ("trailing_zeros", "n", "Count trailing zeros in n factorial for nonnegative n.", (10, 2)),
    ("run_lengths", "values", "Return lengths of consecutive equal-value runs.", ([1, 1, 2], [2, 1])),
    ("middle", "values", "Return the upper-middle element, or None for an empty list.", ([1, 2, 3, 4], 3)),
]
TASKS = tuple(Task(name, f"{name}({params})", prompt, (example,)) for name, params, prompt, example in SPECS)
BY_ID = {task.id: task for task in TASKS}

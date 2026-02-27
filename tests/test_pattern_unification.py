import ast
from dr_source.plugins.pattern.matcher import PatternMatcher

def test_unification():
    print("Testing Metavariable Unification...")
    
    # Test 1: Simple unification in comparison
    matcher = PatternMatcher("$X == $X")
    
    code1 = ast.parse("a == a", mode='eval').body
    print(f"Match '$X == $X' against 'a == a': {matcher.match(code1)} (Expected: True)")
    
    code2 = ast.parse("a == b", mode='eval').body
    print(f"Match '$X == $X' against 'a == b': {matcher.match(code2)} (Expected: False)")

    # Test 2: Multiple metavariables
    matcher = PatternMatcher("foo($X, $Y, $X)")
    
    code3 = ast.parse("foo(1, 2, 1)").body[0].value
    print(f"Match 'foo($X, $Y, $X)' against 'foo(1, 2, 1)': {matcher.match(code3)} (Expected: True)")
    
    code4 = ast.parse("foo(1, 2, 3)").body[0].value
    print(f"Match 'foo($X, $Y, $X)' against 'foo(1, 2, 3)': {matcher.match(code4)} (Expected: False)")

    # Test 3: Complex expressions in metavariables
    matcher = PatternMatcher("result = $X + $X")
    code5 = ast.parse("result = (a + b) + (a + b)").body[0]
    print(f"Match 'result = $X + $X' against 'result = (a + b) + (a + b)': {matcher.match(code5)} (Expected: True)")
    
    code6 = ast.parse("result = (a + b) + (a + c)").body[0]
    print(f"Match 'result = $X + $X' against 'result = (a + b) + (a + c)': {matcher.match(code6)} (Expected: False)")

if __name__ == "__main__":
    test_unification()

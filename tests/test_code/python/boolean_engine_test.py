def check_logic(a, b):
    # SHOULD BE DETECTED: Self comparison
    if a == a:
        print("A is A")
    
    # SHOULD BE IGNORED: pattern-not 1 == 1
    if 1 == 1:
        print("Always true")
        
    # SHOULD BE IGNORED: Different variables
    if a == b:
        print("A is B")

if __name__ == "__main__":
    check_logic(10, 20)

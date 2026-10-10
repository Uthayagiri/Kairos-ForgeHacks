import sys
print(sys.executable)
try:
    import bs4
    print("bs4 available:", bs4.__file__)
except ImportError:
    print("bs4 NOT installed in this interpreter")

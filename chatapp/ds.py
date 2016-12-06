# All Named Tuples Here
from collections import namedtuple

# Represents the Puzzle Certificate
# timestamp is the expiry timestamp of certificate
# difficulty is the number of consecutive 0's from start
# nonce_s is the server nonce
# sign is the signature of the certificate signed by server's pub key
Certificate = namedtuple('Certificate',
                         ['timestamp', 'difficulty', 'nonce_s', 'sign'])


# Represents a solution to the puzzle
# nonce_c is the Client's Nonce
# x is the solution
Solution = namedtuple('Solution', ['nonce_c', 'x'])
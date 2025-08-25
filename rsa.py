import math
import time
import random
#######################################################################################
# Helper functions
#######################################################################################
# used in encode() and decode()
def FME(b, n, m):
    """
    Using the fast modular exponentiation algorithm, returns b**n mod m.
    The function operates with binary expansion of the exponent.

    Parameters:
        b (int): base
        n (int): exponent
        m (int): modulus
    
    Returns:
        int: result of (b^n) mod m
    """
    result = 1
    square = b 
    
    # loop will convert exponent to binary (using mod 2) and continue until all bits of n are processed
    while n > 0:
        k = n % 2 # gets rightmost bit of n
        
        # if current bit is 1, multiply result by current square
        # this effectively saves and accumulates the contribution of each 1 bit in the exponent
        # to the modular exponentiation calculation
        if k == 1: 
            result = (result * square) % m 
        
        # square current value and take mod m
        # matches the square value to the next bit position
        square = (square * square) % m
        
        n = n // 2 # move to next bit using integer division
        
    return result # final value of b^n mod m

# used in pub_keygen() 
def GCD(a, b):
    """
    Calculate the Greatest Common Divisor (GCD) of two integers using the Euclidean Algorithm.

    Parameters:
        a (int): First number
        b (int): Second number

    Returns:
        int: The GCD of a and b
    """
    while b: # EA runs while b is not zero
        # According to the Euclidian Algorithm
        # a becomes b (since GCD(a,b) = GCD(a, (a mod b))
        # b becomes k (a % b)
        a, b = b, a % b 
        
    return a # when b is zero, a should hold the GCD of original (a, b)

# used in priv_keygen()
def EEA(a, b):
    """
    Implements the Extended Euclidean Algorithm to find GCD of a and b along with the Bezout's coefficients.

    Parameters:
        a (int): First number
        b (int): Second number

    Returns:
        tuple: (GCD, (s, t)) where s and t are the Bezout's coefficients
    """
    # input validation: a and b must be positive integers
    if a<= 0 or b <= 0:
        raise ValueError("Both input values must be positive integers.")
    
    # Initialize variables
    m, n = max(a, b), min(a, b) # ensure that m >= n
    # Initial Bezout's coeffs for a, b
    s1, t1 = 1, 0
    s2, t2 = 0, 1
    
    while n > 0:
        q, r = divmod(m, n)  # divmod gives quotient and remainder
        m, n = n, r

        # Update Bezout coefficients
        s1, s2 = s2, s1 - q * s2
        t1, t2 = t2, t1 - q * t2

    # Return GCD and the Bezout coefficients (adjust based on input order)
    return m, (s1, t1) if a > b else (t1, s1)

# Helper function for Find_Public_Key_e and Find_Private_Key_d
def is_prime(n):
    """
    Check if a number is prime.
    
    Parameters:
        n (int): Number to check
    
    Returns:
        bool: True if n is prime, False otherwise
    """
    if n <= 1:
        return False
    if n == 2:
        return True
    if n % 2 == 0:
        return False

    # Check potential divisors up to the integer square root of n
    limit = math.isqrt(n)
    for i in range(3, limit + 1, 2):
        if n % i == 0:
            return False

    return True

# used in encode() 
def text_to_int(_string):
    """
    Convert a string to a list of integers representing the ASCII values of each character.

    Parameters:
        _string (str): The input string to convert.
    
    Returns:
        list: A list of integers corresponding to the ASCII values of the characters in _string.
    
    Raises:
        TypeError: If _string is not a string.
    """
    if not isinstance(_string, str):
        raise TypeError("Input must be a string.")

    # Return the list of ASCII values for each character in the string
    return [ord(char) for char in _string]

# used in decode()
def int_to_text(_list):
    """
    Convert a list of integers (ASCII values) to the corresponding string.

    Parameters:
        _list (list): A list of integers representing ASCII values.
    
    Returns:
        str: A string corresponding to the ASCII values in the input list.
    
    Raises:
        TypeError: If _list is not a list of integers.
        ValueError: If any element in the list is not a valid ASCII integer (0-255).
    """
    if not isinstance(_list, list):
        raise TypeError("Input must be a list.")
    
    # Convert each integer to the corresponding character and join them into a string
    return ''.join(chr(i) for i in _list)

# Helper function for trial division
def trial_division(n):
    """Returns the smallest factor of n using trial division up to sqrt(n)."""
    if n % 2 == 0:
        return 2
    for i in range(3, int(math.sqrt(n)) + 1, 2):
        if n % i == 0:
            return i
    return n  # Return n itself if no factor is found

# Pollard's Rho Algorithm
def pollards_rho(n, max_attempts=100000):
    """Pollard's Rho algorithm for integer factorization."""
    # Function to define the polynomial: x^2 + 1 mod n
    def f(x):
        return (x * x + 1) % n
    
    # Random starting point
    x = random.randint(2, n - 1)
    y = x
    d = 1
    attempts = 0
    
    while d == 1 and attempts < max_attempts:
        x = f(x)  # Move x by one step
        y = f(f(y))  # Move y by two steps
        d = GCD(abs(x - y), n)  # GCD of the difference
        attempts += 1

    if d == n:
        return pollards_rho(n, max_attempts)  # Retry if no factor was found

    if d > 1:
        return d # found a non-trivial factor

    return None # return none if no factor is found within max_attempts

def factorize(n):
    """Factorization function with trial division and Pollard's Rho."""
    # First, try trial division for small factors
    factor = trial_division(n)
    if factor != n:  # If a factor was found
        return [factor, n // factor]

    # If trial division fails (returns n), try Pollard's Rho
    factors = pollards_rho(n)
    if factors:
        return factors

    # If both methods fail, return None (indicating we couldn't factorize n)
    return None

def validate_primes(p, q):
    """Helper to check if both p and q are prime."""
    if not (is_prime(p) and is_prime(q)):
        raise ValueError("Both p and q must be prime numbers.")

#######################################################################################
# Core functions
#######################################################################################
def pub_keygen(p, q):
    """
    Generate the public key for RSA encryption based on two prime numbers p and q.
    
    This function computes:
    1. n = p * q
    2. Euler's totient φ(n) = (p - 1) * (q - 1)
    3. The public exponent e, which is coprime with φ(n) and not equal to p or q
    
    Parameters:
        p (int): A prime number.
        q (int): A prime number.
        
    Returns:
        tuple: A tuple (n, e) representing the public key, where:
            - n is the product of p and q.
            - e is the public exponent.
        
    Raises:
        TypeError: If p or q is not an integer.
        ValueError: If p or q is not prime, or if no suitable e can be found 
    """
   # Validate that p and q are integers
    if not (isinstance(p, int) and isinstance(q, int)):
        raise TypeError("p and q must be integers")
    
    # Validate that p and q are prime
    validate_primes(p, q)

    n = p * q # compute n
    
    # Validate that n is large enough for ASCII encoding
    if n <= 150:
        raise ValueError(f"n = {n} is too small (must be > 150) to safely encode ASCII. Choose larger primes.")
    
    # compute Euler's totient
    phi = (p - 1) * (q - 1)
    
    # relative prime check for e, start with smallest possible e = 3
    e = 3

    # loop finds smallest possible valid e
    # Requirements for e:
    # - e is coprime with phi
    # - e is not equal to p or q
    # - e is less than phi
    while e < phi:
        if GCD(e, phi) == 1 and e != p and e != q:
            break
        e += 2  # Increment by 2 to check the next odd number
    
    else:
        # If no suitable e is found within the range
        raise ValueError("Could not find a suitable e. Please make sure that the primes p and q are large enough.")
    
    return n, e

def priv_keygen(e, p, q):
    """
    Generate the private key for RSA encryption based on public exponent e, and two prime numbers p and q.

    This function calculates the private key exponent d such that:
    1. d * e ≡ 1 (mod φ(n)), where φ(n) = (p - 1) * (q - 1)
    2. e must be coprime with φ(n) (gcd(e, φ(n)) = 1)

    Parameters:
        e (int): The public exponent.
        p (int): A prime number.
        q (int): A prime number.
        
    Returns:
        int: The private exponent d, such that d * e ≡ 1 (mod φ(n)).

    Raises:
        TypeError: If p or q are not integers.
        ValueError: If p or q are not prime, if e is not coprime with φ(n), or if d is not found.
    """
    
    # Validate that p and q are integers
    if not (isinstance(p, int) and isinstance(q, int)):
        raise TypeError("p and q must be integers")
    
    # Validate that p and q are prime
    validate_primes(p, q)

    # Calclulate Euler's totient
    phi = (p - 1) * (q - 1)
    
    # Find d using EEA
    gcd, bezout_coeffs = EEA(e, phi) # unpack coeffs
    d = bezout_coeffs[0] # extract d from first coeff
    
    # Verify that e and phi are coprime
    if gcd != 1:
        raise ValueError("e must be coprime with phi")
    
    # Make sure d is positive
    d = d % phi
    
    # Verify d is valid: d * e is congruent to 1 mod phi
    if (d * e) % phi != 1:
        raise ValueError("Failed to find valid private key")
        
    return d # return if d is valid


def encode(n, e, message):
    """
    Encrypts a given message using RSA encryption.

    Parameters:
        n (int): The modulus of the public key (n = p * q).
        e (int): The public exponent.
        message (str): The plaintext message to encrypt.

    Returns:
        list: A list of integers representing the encrypted cipher text.
    """
    # Convert the message to a list of ASCII values
    integer_list = text_to_int(message)
    
    # Encrypt each number using the RSA encryption formula
    # C = M^e % n
    cipher_text = [FME(m, e, n) for m in integer_list]
    
    return cipher_text

def decode(n, d, cipher_text):
    """
    Decrypts an RSA-encrypted message.

    Parameters:
        n (int): The modulus of the private key.
        d (int): The private exponent.
        cipher_text (list): The encrypted message as a list of integers (cipher text).

    Returns:
        str: The decrypted plaintext message.
    """
    # decrypt each integer in cipher_text using RSA decryption formula
    decrypted_numbers = [FME(c, d, n) for c in cipher_text]   

    # Convert the decrypted numbers (ASCII values) back to the original message
    message = int_to_text(decrypted_numbers) 
        
    return message

# Main Menu Function
def print_menu():
    ascii_art = """
  ____  ____    _                                     
 |  _ \/ ___|  / \                                    
 | |_) \___ \ / _ \                                   
 |  _ < ___) / ___ \                                  
 |_|_\_\____/_/   \_\               _   _             
 | ____|_ __   ___ _ __ _   _ _ __ | |_(_) ___  _ __  
 |  _| | '_ \ / __| '__| | | | '_ \| __| |/ _ \| '_ \ 
 | |___| | | | (__| |  | |_| | |_) | |_| | (_) | | | |
 |_____|_| |_|\___|_|   \__, | .__/ \__|_|\___/|_| |_|
 / ___| _   _ ___| |_ __|___/|_|__                    
 \___ \| | | / __| __/ _ \ '_ ` _ \                   
  ___) | |_| \__ \ ||  __/ | | | | |                  
 |____/ \__, |___/\__\___|_| |_| |_|                  
        |___/                                         

    Welcome to the RSA Encryption System!
    =======================================
    Please choose an option:
    1. Generate Keys
    2. Encode Message
    3. Decode Message
    4. Break Code (Factorize and find keys)
    5. Exit
    """
    print(ascii_art)

def menu():
    while True:
        print_menu()  # Display the ASCII art menu
        
        print("\nPlease choose an option from the menu:")
        choice = input("Enter your choice (1-5): ").strip()

        if choice == '1':
            # Generate RSA keys
            print("\n--- Generate RSA Keys ---")
            try:
                p = int(input("Enter a prime number p: "))
                q = int(input("Enter a prime number q: "))
                n, e = pub_keygen(p, q)
                print(f"Public Key (n, e): ({n}, {e})")
                d = priv_keygen(e, p, q)
                print(f"Private Key (n, d): ({n}, {d})\n")
            except Exception as e:
                print(f"Error: {e}\n")

        elif choice == '2':
            # Encode a message
            print("\n--- Encode Message ---")
            try:
                n = int(input("Enter the modulus n (from the public key): "))
                e = int(input("Enter the public exponent e (from the public key): "))
                message = input("Enter the message to encode: ")
                cipher_text = encode(n, e, message)
                print(f"Encoded Message: {cipher_text}\n")
            except Exception as e:
                print(f"Error: {e}\n")

        elif choice == '3':
            # Decode a message
            print("\n--- Decode Message ---")
            try:
                n = int(input("Enter the modulus n (from the private key): "))
                d = int(input("Enter the private exponent d (from the private key): "))
                
                # Accept comma-delimited list of integers for encoded message
                cipher_text_str = input("Enter the encoded message (as a comma-delimited Python list): ")
                
                # Convert string input into a list of integers (remove spaces and convert)
                cipher_text = list(map(int, cipher_text_str.strip('[]').split(',')))
                decoded_message = decode(n, d, cipher_text)
                print(f"Decoded Message: {decoded_message}\n")
            except ValueError:
                print("Invalid input. Please enter a valid comma-delimited list of integers.\n")

        elif choice == '4':
            # Break Code: Factorize n and find keys
            print("\n--- Break Code ---")
            try:
                encrypted_message_str = input("Enter the encrypted message (as a comma-delimited Python list): ")
                
                # Convert string input into a list of integers (remove spaces and convert)
                encrypted_message = list(map(int, encrypted_message_str.strip('[]').split(',')))
                
                # Accept public key (n, e) for factorization
                n = int(input("Enter the modulus n (from the public key): "))
                e = int(input("Enter the public exponent e (from the public key): "))
                
                print(f"\nAttempting to factorize n: {n}...")
                
                # Factorize n and attempt to recover the keys
                factors = factorize(n)
                
                if isinstance(factors, list) and len(factors) == 2:
                    p, q = factors
                    print(f"Factors of n: {p}, {q}")
                    try:
                        # Recover public key and private key
                        n, e = pub_keygen(p, q)
                        d = priv_keygen(e, p, q)
                        print(f"Recovered public key (n, e): ({n}, {e})")
                        print(f"Recovered private key (n, d): ({n}, {d})\n")
                        
                        # Now decode the message using the recovered private key
                        decoded_message = decode(n, d, encrypted_message)
                        print(f"Decoded Message: {decoded_message}\n")
                    except Exception as e:
                        print(f"Error in key recovery: {e}\n")
                else:
                    print("Could not factorize n into two prime factors.\n")
            except ValueError:
                print("Invalid input. Please enter a valid comma-delimited list of integers.\n")

        elif choice == '5':
            print("\nExiting the program. Goodbye!")
            break  # Exit the menu loop when user chooses to exit

        else:
            print("\nInvalid choice. Please try again.\n")

# Run the program
if __name__ == "__main__":
    menu()

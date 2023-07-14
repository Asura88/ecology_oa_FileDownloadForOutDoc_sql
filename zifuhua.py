import pyfiglet

def generate_ascii_art(text):
    ascii_art = pyfiglet.figlet_format(text)
    return ascii_art

def main():
    text = "Mannix"
    ascii_art = generate_ascii_art(text)
    print(ascii_art)

if __name__ == "__main__":
    main()

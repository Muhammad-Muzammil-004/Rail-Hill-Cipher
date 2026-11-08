"""CLI entry point."""
import sys
import custom_cipher
import attacks


def main():
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python main.py encrypt <key> <plaintext>")
        print("  python main.py decrypt <key> <ciphertext>")
        print("  python main.py attack <ciphertext> <known_plaintext>")
        print("  python main.py gui")
        return
    cmd = sys.argv[1]
    if cmd == "gui":
        import gui
        gui.App().mainloop()
        return
    if cmd == "encrypt":
        key = sys.argv[2]
        pt = " ".join(sys.argv[3:])
        print(custom_cipher.encrypt(pt, key))
    elif cmd == "decrypt":
        key = sys.argv[2]
        ct = " ".join(sys.argv[3:])
        print(custom_cipher.decrypt(ct, key))
    elif cmd == "attack":
        ct = sys.argv[2]
        known = sys.argv[3]
        res = attacks.known_plaintext_attack(ct, known)
        if res is None:
            print("Attack failed")
        else:
            K, r, recovered = res
            print("rails:", r)
            print("matrix:", K)
            print("recovered:", recovered)
    else:
        print("Unknown command")


if __name__ == "__main__":
    main()

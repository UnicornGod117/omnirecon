#!/usr/bin/env python3
import os
import requests

OUI_URL = "https://standards-oui.ieee.org/oui/oui.txt"
# Always write next to this script, not the working directory
OUI_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "oui.txt")
_BLOCK = 32 * 1024  # 32 KB blocks


def update_oui() -> None:
    """Downloads the latest IEEE OUI file and saves it next to this script."""
    print(f"Connecting to {OUI_URL} …")
    try:
        response = requests.get(OUI_URL, stream=True, timeout=30)
        response.raise_for_status()

        total_size = int(response.headers.get("content-length", 0))
        downloaded = 0
        print(f"Downloading {os.path.basename(OUI_FILE)}"
              + (f" ({total_size / (1024 * 1024):.2f} MB)" if total_size else "") + " …")

        with open(OUI_FILE, "wb") as f:
            for chunk in response.iter_content(_BLOCK):
                f.write(chunk)
                downloaded += len(chunk)
                if total_size:
                    pct = downloaded * 100 // total_size
                    print(f"\r  {pct:3d}%  {downloaded // 1024} / {total_size // 1024} KB",
                          end="", flush=True)
                else:
                    print(f"\r  {downloaded // 1024} KB downloaded",
                          end="", flush=True)

        print()  # newline after progress
        actual = os.path.getsize(OUI_FILE)
        if total_size and actual != total_size:
            print(f"  ⚠  Size mismatch: expected {total_size} B, got {actual} B")
        else:
            print(f"Update complete → {OUI_FILE}  ({actual // 1024} KB)")

    except Exception as e:
        print(f"\nError: could not update OUI file. {e}")


if __name__ == "__main__":
    update_oui()

import sys
from dulwich import porcelain

def main():
    if len(sys.argv) > 1:
        token = sys.argv[1].strip()
    else:
        token = input("Enter your GitHub Personal Access Token: ").strip()

    if not token:
        print("Error: No GitHub token provided.")
        sys.exit(1)

    remote_url = f"https://{token}@github.com/rohitkumar8083/SafeLinks.git"
    print("Pushing to https://github.com/rohitkumar8083/SafeLinks.git [main]...")
    try:
        porcelain.push("D:/SafeLinks", remote_url, "refs/heads/main")
        print("\nSUCCESS: All commits successfully pushed to GitHub repository!")
    except Exception as e:
        print(f"\nPush failed: {e}")

if __name__ == "__main__":
    main()

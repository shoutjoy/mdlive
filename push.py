import subprocess


def run(cmd: list[str]) -> subprocess.CompletedProcess:
    print(f"+ {' '.join(cmd)}")
    return subprocess.run(cmd, check=False)


def require_ok(result: subprocess.CompletedProcess, context: str) -> None:
    if result.returncode != 0:
        raise SystemExit(f"{context} (exit {result.returncode})")


def main() -> int:
    inside = subprocess.run(
        ["git", "rev-parse", "--is-inside-work-tree"],
        capture_output=True,
        text=True,
        check=False,
    )
    if inside.returncode != 0 or inside.stdout.strip().lower() != "true":
        print("Not inside a git repository.")
        return 2

    message = input("Commit message: ").strip()
    if not message:
        print("Aborted: empty commit message.")
        return 1

    add_res = run(["git", "add", "."])
    require_ok(add_res, "git add failed")

    staged = subprocess.run(["git", "diff", "--cached", "--quiet"], check=False)
    if staged.returncode == 0:
        print("No staged changes. Nothing to commit; pushing anyway.")
    elif staged.returncode == 1:
        commit_res = run(["git", "commit", "-m", message])
        require_ok(commit_res, "git commit failed")
    else:
        print("Failed to determine staged changes.")
        return 2

    push_res = run(["git", "push"])
    require_ok(push_res, "git push failed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

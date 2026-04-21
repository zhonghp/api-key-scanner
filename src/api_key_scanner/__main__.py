"""`python -m api_key_scanner` and `api-key-scanner-mcp` console script entrypoint."""

from api_key_scanner.server import run


def main() -> None:
    run()


if __name__ == "__main__":
    main()

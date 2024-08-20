import subprocess
import sys

# pip install PyYAML
import yaml


def lint_keys(data, keys):
    """Recursively lint the given data.
    """
    for k, v in data.items():
        if isinstance(v, dict):
            lint_keys(v, keys)
        elif k in keys:
            # NOTE: We use `--ext=.md` since the Petstore example
            # uses Markdown formatting in its descriptions.
            print(subprocess.check_output(["vale", "--ext=.md", "--no-exit", v]))


def lint(spec, keys):
    """A lint a given OpenAPI specification file.
    """
    with open(spec, "r") as s:
        doc = yaml.safe_load(s)
        # print(doc)
        lint_keys(doc, keys)


if __name__ == "__main__":
    lint(
        sys.argv[1],

        # A list of the keys we want to lint:
        keys=["description", "how_to_implement", "known_false_positives"],
    )
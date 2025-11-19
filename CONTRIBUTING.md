# Contributing to PyFileEncryptTool

Thanks for checking out the project! We are happy you want to help make this tool better.

Whether you are fixing a bug, improving documentation, or adding a new feature, your help is appreciated.

## How You Can Help

### Reporting Bugs
If you find something broken, let us know. Check the **Issues** tab first to see if it has already been reported. If not, create a new "Bug Report" using the provided template. Please include details like your OS and the steps to reproduce the error so we can track it down.

### Suggesting Features
Have an idea? We would love to hear it. Open a "Feature Request" issue and tell us what you have in mind.

### Writing Code
If you want to get your hands dirty with the code:
1.  Fork the repository and clone it locally.
2.  Create a new branch for your changes.
3.  Make your updates.
4.  Run the tests to ensure everything still works (see below).
5.  Submit a Pull Request.

## Setting Up Your Environment

You will need Python 3.9 or higher. We recommend using a virtual environment to keep your dependencies clean.

```bash
# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate  # macOS/Linux
# or venv\Scripts\activate on Windows
```

```bash
# Install dependencies
pip install -r requirements.txt
````

## Running Tests

We use `unittest` to ensure the encryption and decryption logic remains secure and stable. Please run the tests before submitting your changes.

To run the full test suite:

```bash
python -m unittest test_decrypt_file -v
```

For more specific testing details, check out `TEST_DOCUMENTATION.md`.

## Code Style

We try to keep things consistent to make the code easy to read for everyone.

  * **Python**: We follow standard Python coding conventions.
  * **General**: This project includes an `.editorconfig` and `.prettierrc` file. Please make sure your editor respects these settings for indentation and formatting.

## Submitting a Pull Request

When you are ready, push your branch to your fork and open a Pull Request. Please describe what you changed and link to any related issues. We will review it as soon as we can.

Thanks again for contributing!
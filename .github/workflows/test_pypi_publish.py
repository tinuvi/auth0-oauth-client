import shlex
import subprocess

from pathlib import Path
from typing import List
from typing import Union


def execute_command(command: Union[List[str], str], path=None) -> str:
    if not path:
        path = Path("./").resolve()

    print(f"{execute_command.__name__}: current path: {path}")

    subprocess_params = {"capture_output": True, "encoding": "utf8", "cwd": str(path)}
    if type(command) is not str:
        return subprocess.run(command, **subprocess_params).stdout
    else:
        process_list = list()
        previous_process = None
        for command_part in command.split("|"):
            args = shlex.split(command_part)
            if previous_process is None:
                process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=str(path))
            else:
                process = subprocess.Popen(
                    args, stdin=previous_process.stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=str(path)
                )
            process_list.append(process)
            previous_process = process
        last_process = process_list[-1]
        output, errors = last_process.communicate()
        result = output.decode("utf-8", "ignore")
        if errors:
            result += errors.decode("utf-8", "ignore")
        return result


def increase_version_to_test_pypi(path=None):
    result = execute_command(["poetry", "version", "prerelease"], path=path)
    print(result.strip())
    new_version = execute_command(["poetry", "version", "-s"], path=path).strip()
    return new_version


def publish_test_pypi(number_of_tries=20, path=None):
    first_command = "yes"
    second_command = "poetry publish --build --repository testpypi"
    command_to_publish = "|".join([first_command, second_command])
    uploaded = False

    current_version = execute_command(["poetry", "version", "-s"], path=path).strip()
    print(f"Trying version: {current_version}")
    result = execute_command(command_to_publish, path=path)
    if any(error in result for error in ("UploadError", "File already exists")):
        for index in range(0, number_of_tries):
            new_version = increase_version_to_test_pypi(path=path)
            print(f"Trying version: {new_version}")
            result = execute_command(command_to_publish, path=path)
            print(f"Received result from pypi: {result}")
            if any(error in result for error in ("UploadError", "File already exists")):
                continue
            else:
                uploaded = True
                break

    if not uploaded:
        print("Could not upload the package")
        exit(1)
    print("Done!")

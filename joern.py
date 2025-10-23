import os
import subprocess

# parameters: directory containing c files to scan and optional boolean overwrite flag which currently defaults to True
def run_joern_scan(directory, overwrite=True):
    results = {}

    # command to execute joern-scan
    call_scan = ['joern-scan']

    # force joern-scan to generate a fresh cpg
    if overwrite:
        call_scan.append('--overwrite')

    # scan every file in supplied directory
    for filename in os.listdir(directory):
        filepath = os.path.join(directory, filename)

        # won't try to scan directories
        if os.path.isfile(filepath):

            try:
                process = subprocess.run(
                    call_scan + [filepath],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )

                # output contains both standard output and any errors
                output = process.stdout + process.stderr
                # clear result from previous scans
                result_line = None
                for line in output.splitlines():
                    # look for the result line and save it
                    if line.startswith("Result:"):
                        result_line = line
                        break

                results[filename] = result_line


                print(f'processed {filename}: {result_line}')

            # handle any errors
            except Exception as e:
                print(f'error processing {filename}: {e}')
                results[filename] = {
                    'result': None,
                    'error': str(e)
                }
    return results

def parse_result_line(result_line):
    """
    Given a result line like:
    "Result: 3.0 : Unchecked read/recv/malloc: fstring4.c:36:main"

    This function returns a tuple with:
    (severity, type, filename, line, caller)

    If the format is unexpected, returns a tuple of Nones.
    """
    if not isinstance(result_line, str) or not result_line.startswith("Result:"):
        return (None, None, None, None, None)

    # Remove the "Result:" prefix and strip whitespace
    trimmed = result_line[len("Result:"):].strip()
    # Split on colons and strip each part
    parts = [part.strip() for part in trimmed.split(':')]

    # Check if we have at least 5 parts
    if len(parts) < 5:
        return (None, None, None, None, None)

    severity = parts[0]
    type_str = parts[1]
    filename = parts[2]
    line_number = parts[3]
    caller = parts[4]

    return (severity, type_str, filename, line_number, caller)

def run_joern_parse(directory):
    """
    Given a codepath, runs joern-parse on it to generate CPG data.
    """
    try:
        process = subprocess.run(
            ['joern-parse', directory],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        # output contains both standard output and any errors
        output = process.stdout + process.stderr
        print(f'joern-parse output for {directory}:\n{output}')

    except Exception as e:
        print(f'error running joern-parse on {directory}: {e}')


def run_joern_export(output_directory):
    """
    Given an output directory, runs joern-export to export CPG data to CSV files.
    """
    try:
        process = subprocess.run(
            ['joern-export --repr=all --format=neo4jcsv --out=', output_directory],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        # output contains both standard output and any errors
        output = process.stdout + process.stderr
        print(f'joern-export output for {output_directory}:\n{output}')

    except Exception as e:
        print(f'error running joern-export on {output_directory}: {e}')
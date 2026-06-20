import os
import re
import subprocess

from lib.core.common import openFile
from lib.core.convert import getText

def getRevisionNumber():

    retVal = None
    filePath = None
    directory = os.path.dirname(__file__)

    while True:
        candidate = os.path.join(directory, ".git", "HEAD")
        if os.path.exists(candidate):
            filePath = candidate
            break

        parent = os.path.dirname(directory)
        if parent == directory:
            break
        directory = parent

    if filePath:
        with openFile(filePath, "r") as f:
            content = getText(f.read()).strip()

            if content.startswith("ref: "):
                ref_path = content.replace("ref: ", "").strip()
                filePath = os.path.join(directory, ".git", ref_path)

                if os.path.exists(filePath):
                    with openFile(filePath, "r") as f_ref:
                        content = getText(f_ref.read()).strip()

            match = re.match(r"(?i)[0-9a-f]{40}", content)
            retVal = match.group(0) if match else None

    if not retVal:
        try:
            process = subprocess.Popen(["git", "rev-parse", "--verify", "HEAD"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, _ = process.communicate()
            match = re.search(r"(?i)[0-9a-f]{40}", getText(stdout or ""))
            retVal = match.group(0) if match else None
        except:
            pass

    return retVal[:7] if retVal else None

from lib.core.compat import xrange
from lib.core.enums import PRIORITY
from lib.core.settings import REPLACEMENT_MARKER

__priority__ = PRIORITY.HIGHEST

def dependencies():
    pass

def tamper(payload, **kwargs):

    if payload and payload.find("IF") > -1:
        payload = payload.replace("()", REPLACEMENT_MARKER)
        while payload.find("IF(") > -1:
            index = payload.find("IF(")
            depth = 1
            commas, end = [], None

            for i in xrange(index + len("IF("), len(payload)):
                if depth == 1 and payload[i] == ',':
                    commas.append(i)

                elif depth == 1 and payload[i] == ')':
                    end = i
                    break

                elif payload[i] == '(':
                    depth += 1

                elif payload[i] == ')':
                    depth -= 1

            if len(commas) == 2 and end:
                a = payload[index + len("IF("):commas[0]].strip("()")
                b = payload[commas[0] + 1:commas[1]].lstrip().strip("()")
                c = payload[commas[1] + 1:end].lstrip().strip("()")
                newVal = "CASE WHEN (%s) THEN (%s) ELSE (%s) END" % (a, b, c)
                payload = payload[:index] + newVal + payload[end + 1:]
            else:
                break

        payload = payload.replace(REPLACEMENT_MARKER, "()")

    return payload

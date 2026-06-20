class _Getch(object):
    def __init__(self):
        try:
            self.impl = _GetchWindows()
        except ImportError:
            try:
                self.impl = _GetchMacCarbon()
            except (AttributeError, ImportError):
                self.impl = _GetchUnix()

    def __call__(self):
        return self.impl()

class _GetchUnix(object):
    def __init__(self):
        __import__("tty")

    def __call__(self):
        import sys
        import termios
        import tty

        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        try:
            tty.setraw(sys.stdin.fileno())
            ch = sys.stdin.read(1)
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
        return ch

class _GetchWindows(object):
    def __init__(self):
        __import__("msvcrt")

    def __call__(self):
        import msvcrt
        return msvcrt.getch()

class _GetchMacCarbon(object):
    def __init__(self):
        import Carbon

        getattr(Carbon, "Evt")  # see if it has this (in Unix, it doesn't)

    def __call__(self):
        import Carbon

        if Carbon.Evt.EventAvail(0x0008)[0] == 0:  # 0x0008 is the keyDownMask
            return ''
        else:
            (what, msg, when, where, mod) = Carbon.Evt.GetNextEvent(0x0008)[1]
            return chr(msg & 0x000000FF)

getch = _Getch()

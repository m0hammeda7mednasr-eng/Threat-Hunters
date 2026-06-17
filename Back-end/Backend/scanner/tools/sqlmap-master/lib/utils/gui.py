import os
import re
import socket
import subprocess
import sys
import tempfile
import threading
import webbrowser

from lib.core.common import getSafeExString
from lib.core.common import saveConfig
from lib.core.data import paths
from lib.core.defaults import defaults
from lib.core.enums import MKSTEMP_PREFIX
from lib.core.exception import SqlmapMissingDependence
from lib.core.exception import SqlmapSystemException
from lib.core.settings import DEV_EMAIL_ADDRESS
from lib.core.settings import IS_WIN
from lib.core.settings import ISSUES_PAGE
from lib.core.settings import GIT_PAGE
from lib.core.settings import SITE
from lib.core.settings import VERSION_STRING
from lib.core.settings import WIKI_PAGE
from thirdparty.six.moves import queue as _queue

alive = None
line = ""
process = None
queue = None

def runGui(parser):
    try:
        from thirdparty.six.moves import tkinter as _tkinter
        from thirdparty.six.moves import tkinter_scrolledtext as _tkinter_scrolledtext
        from thirdparty.six.moves import tkinter_ttk as _tkinter_ttk
        from thirdparty.six.moves import tkinter_messagebox as _tkinter_messagebox
    except ImportError as ex:
        raise SqlmapMissingDependence("missing dependence ('%s')" % getSafeExString(ex))

    class ConstrainedEntry(_tkinter.Entry):
        def __init__(self, master=None, **kwargs):
            self.var = _tkinter.StringVar()
            self.regex = kwargs["regex"]
            del kwargs["regex"]
            _tkinter.Entry.__init__(self, master, textvariable=self.var, **kwargs)
            self.old_value = ''
            self.var.trace('w', self.check)
            self.get, self.set = self.var.get, self.var.set

        def check(self, *args):
            if re.search(self.regex, self.get()):
                self.old_value = self.get()
            else:
                self.set(self.old_value)

    try:
        window = _tkinter.Tk()
    except Exception as ex:
        errMsg = "unable to create GUI window ('%s')" % getSafeExString(ex)
        raise SqlmapSystemException(errMsg)

    window.title("sqlmap - Tkinter GUI")

    bg_color = "#f5f5f5"
    fg_color = "#333333"
    accent_color = "#2c7fb8"
    window.configure(background=bg_color)

    style = _tkinter_ttk.Style()

    available_themes = style.theme_names()
    if 'clam' in available_themes:
        style.theme_use('clam')
    elif 'alt' in available_themes:
        style.theme_use('alt')

    style.configure("TNotebook", background=bg_color)
    style.configure("TNotebook.Tab",
                   padding=[10, 4],
                   background="#e1e1e1",
                   font=('Helvetica', 9))
    style.map("TNotebook.Tab",
             background=[("selected", accent_color), ("active", "#7fcdbb")],
             foreground=[("selected", "white"), ("active", "white")])

    style.configure("TButton",
                   padding=4,
                   relief="flat",
                   background=accent_color,
                   foreground="white",
                   font=('Helvetica', 9))
    style.map("TButton",
             background=[('active', '#41b6c4')])

    def center(window):
        window.update_idletasks()
        width = window.winfo_width()
        frm_width = window.winfo_rootx() - window.winfo_x()
        win_width = width + 2 * frm_width
        height = window.winfo_height()
        titlebar_height = window.winfo_rooty() - window.winfo_y()
        win_height = height + titlebar_height + frm_width
        x = window.winfo_screenwidth() // 2 - win_width // 2
        y = window.winfo_screenheight() // 2 - win_height // 2
        window.geometry('{}x{}+{}+{}'.format(width, height, x, y))
        window.deiconify()

    def onKeyPress(event):
        global line
        global queue

        if process:
            if event.char == '\b':
                line = line[:-1]
            else:
                line += event.char

    def onReturnPress(event):
        global line
        global queue

        if process:
            try:
                process.stdin.write(("%s\n" % line.strip()).encode())
                process.stdin.flush()
            except socket.error:
                line = ""
                event.widget.master.master.destroy()
                return "break"
            except:
                return

            event.widget.insert(_tkinter.END, "\n")

            return "break"

    def run():
        global alive
        global process
        global queue

        config = {}

        for key in window._widgets:
            dest, widget_type = key
            widget = window._widgets[key]

            if hasattr(widget, "get") and not widget.get():
                value = None
            elif widget_type == "string":
                value = widget.get()
            elif widget_type == "float":
                value = float(widget.get())
            elif widget_type == "int":
                value = int(widget.get())
            else:
                value = bool(widget.var.get())

            config[dest] = value

        for option in parser.option_list:
            if option.dest not in config or config[option.dest] is None:
                config[option.dest] = defaults.get(option.dest, None)

        handle, configFile = tempfile.mkstemp(prefix=MKSTEMP_PREFIX.CONFIG, text=True)
        os.close(handle)

        saveConfig(config, configFile)

        def enqueue(stream, queue):
            global alive

            for line in iter(stream.readline, b''):
                queue.put(line)

            alive = False
            stream.close()

        alive = True

        process = subprocess.Popen([sys.executable or "python", os.path.join(paths.SQLMAP_ROOT_PATH, "sqlmap.py"), "-c", configFile], shell=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE, bufsize=1, close_fds=not IS_WIN)

        queue = _queue.Queue()
        thread = threading.Thread(target=enqueue, args=(process.stdout, queue))
        thread.daemon = True
        thread.start()

        top = _tkinter.Toplevel()
        top.title("Console")
        top.configure(background=bg_color)

        console_frame = _tkinter.Frame(top, bg=bg_color)
        console_frame.pack(fill=_tkinter.BOTH, expand=True, padx=10, pady=10)

        text = _tkinter_scrolledtext.ScrolledText(console_frame, undo=True, wrap=_tkinter.WORD,
                                                bg="#2c3e50", fg="#ecf0f1",
                                                insertbackground="white",
                                                font=('Consolas', 10))
        text.bind("<Key>", onKeyPress)
        text.bind("<Return>", onReturnPress)
        text.pack(fill=_tkinter.BOTH, expand=True)
        text.focus()

        center(top)

        while True:
            line = ""
            try:
                line = queue.get(timeout=.1)
                text.insert(_tkinter.END, line)
            except _queue.Empty:
                text.see(_tkinter.END)
                text.update_idletasks()

                if not alive:
                    break

    menubar = _tkinter.Menu(window, bg=bg_color, fg=fg_color)

    filemenu = _tkinter.Menu(menubar, tearoff=0, bg=bg_color, fg=fg_color)
    filemenu.add_command(label="Open", state=_tkinter.DISABLED)
    filemenu.add_command(label="Save", state=_tkinter.DISABLED)
    filemenu.add_separator()
    filemenu.add_command(label="Exit", command=window.quit)
    menubar.add_cascade(label="File", menu=filemenu)

    menubar.add_command(label="Run", command=run)

    helpmenu = _tkinter.Menu(menubar, tearoff=0, bg=bg_color, fg=fg_color)
    helpmenu.add_command(label="Official site", command=lambda: webbrowser.open(SITE))
    helpmenu.add_command(label="Github pages", command=lambda: webbrowser.open(GIT_PAGE))
    helpmenu.add_command(label="Wiki pages", command=lambda: webbrowser.open(WIKI_PAGE))
    helpmenu.add_command(label="Report issue", command=lambda: webbrowser.open(ISSUES_PAGE))
    helpmenu.add_separator()
    helpmenu.add_command(label="About", command=lambda: _tkinter_messagebox.showinfo("About", "%s\n\n    (%s)" % (VERSION_STRING, DEV_EMAIL_ADDRESS)))
    menubar.add_cascade(label="Help", menu=helpmenu)

    window.config(menu=menubar, bg=bg_color)
    window._widgets = {}

    header_frame = _tkinter.Frame(window, bg=bg_color, height=60)
    header_frame.pack(fill=_tkinter.X, pady=(0, 5))
    header_frame.pack_propagate(0)

    title_label = _tkinter.Label(header_frame, text="Configuration",
                                font=('Helvetica', 14),
                                fg=accent_color, bg=bg_color)
    title_label.pack(side=_tkinter.LEFT, padx=15)

    run_button = _tkinter_ttk.Button(header_frame, text="Run", command=run, width=12)
    run_button.pack(side=_tkinter.RIGHT, padx=15)

    notebook = _tkinter_ttk.Notebook(window)
    notebook.pack(expand=1, fill="both", padx=5, pady=(0, 5))

    tab_frames = {}
    tab_canvases = {}
    tab_scrollable_frames = {}
    tab_groups = {}

    for group in parser.option_groups:
        tab_frame = _tkinter.Frame(notebook, bg=bg_color)
        tab_frames[group.title] = tab_frame

        canvas = _tkinter.Canvas(tab_frame, bg=bg_color, highlightthickness=0)
        scrollbar = _tkinter_ttk.Scrollbar(tab_frame, orient="vertical", command=canvas.yview)
        scrollable_frame = _tkinter.Frame(canvas, bg=bg_color)

        tab_canvases[group.title] = canvas
        tab_scrollable_frames[group.title] = scrollable_frame
        tab_groups[group.title] = group

        scrollable_frame.bind(
            "<Configure>",
            lambda e, canvas=canvas: canvas.configure(scrollregion=canvas.bbox("all"))
        )

        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        notebook.add(tab_frame, text=group.title)

        loading_label = _tkinter.Label(scrollable_frame, text="Loading options...",
                                     font=('Helvetica', 12),
                                     fg=accent_color, bg=bg_color)
        loading_label.pack(expand=True)

    def populate_tab(tab_name):
        group = tab_groups[tab_name]
        scrollable_frame = tab_scrollable_frames[tab_name]
        canvas = tab_canvases[tab_name]

        for child in scrollable_frame.winfo_children():
            child.destroy()

        row = 0

        if group.get_description():
            desc_label = _tkinter.Label(scrollable_frame, text=group.get_description(),
                                      wraplength=600, justify="left",
                                      font=('Helvetica', 9),
                                      fg="#555555", bg=bg_color)
            desc_label.grid(row=row, column=0, columnspan=3, sticky="w", padx=10, pady=(10, 5))
            row += 1

        for option in group.option_list:
            option_label = _tkinter.Label(scrollable_frame,
                                        text=parser.formatter._format_option_strings(option) + ":",
                                        font=('Helvetica', 9),
                                        fg=fg_color, bg=bg_color,
                                        anchor="w")
            option_label.grid(row=row, column=0, sticky="w", padx=10, pady=2)

            if option.type == "string":
                widget = _tkinter.Entry(scrollable_frame, font=('Helvetica', 9),
                                      relief="sunken", bd=1, width=20)
                widget.grid(row=row, column=1, sticky="w", padx=5, pady=2)
            elif option.type == "float":
                widget = ConstrainedEntry(scrollable_frame, regex=r"\A\d*\.?\d*\Z",
                                        font=('Helvetica', 9),
                                        relief="sunken", bd=1, width=10)
                widget.grid(row=row, column=1, sticky="w", padx=5, pady=2)
            elif option.type == "int":
                widget = ConstrainedEntry(scrollable_frame, regex=r"\A\d*\Z",
                                        font=('Helvetica', 9),
                                        relief="sunken", bd=1, width=10)
                widget.grid(row=row, column=1, sticky="w", padx=5, pady=2)
            else:
                var = _tkinter.IntVar()
                widget = _tkinter.Checkbutton(scrollable_frame, variable=var,
                                            bg=bg_color, activebackground=bg_color)
                widget.var = var
                widget.grid(row=row, column=1, sticky="w", padx=5, pady=2)

            help_text = option.help
            if len(help_text) > 100:
                help_text = help_text[:100] + "..."

            help_label = _tkinter.Label(scrollable_frame, text=help_text,
                                      font=('Helvetica', 8),
                                      fg="#666666", bg=bg_color,
                                      wraplength=400, justify="left")
            help_label.grid(row=row, column=2, sticky="w", padx=5, pady=2)

            window._widgets[(option.dest, option.type)] = widget

            default = defaults.get(option.dest)
            if default:
                if hasattr(widget, "insert"):
                    widget.insert(0, default)
                elif hasattr(widget, "var"):
                    widget.var.set(1 if default else 0)

            row += 1

        _tkinter.Label(scrollable_frame, bg=bg_color, height=1).grid(row=row, column=0)

        canvas.update_idletasks()
        canvas.configure(scrollregion=canvas.bbox("all"))

        window.update_idletasks()

    def populate_tabs_background():
        for tab_name in tab_groups.keys():
            window.after(100, lambda name=tab_name: populate_tab(name))

    window.after(500, populate_tabs_background)

    window.update()
    window.minsize(800, 500)

    center(window)

    window.mainloop()

import tkinter as tk
import ttkbootstrap as ttk
from ttkbootstrap import Style
from compressor import FileCompressorApp
from decompressor import FileDecompressorApp
from ttkbootstrap.constants import *
import sys
import os
import ctypes


def resource_path(relative_path):
    """
    Obtiene la ruta absoluta de un recurso, compatible con desarrollo y PyInstaller.

    Args:
        relative_path (str): Ruta relativa del recurso (ej. ícono, imagen, etc.).

    Returns:
        str: Ruta absoluta válida para acceder al recurso.
    """
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)


class MainApp:
    """
    Aplicación principal con interfaz gráfica para compresión y descompresión.

    Crea una ventana con pestañas para:
    - Comprimir archivos o carpetas
    - Descomprimir o desencriptar archivos

    Usa ttkbootstrap para una apariencia moderna.
    """
    def __init__(self, master):
        self.master = master
        master.title("PackIt!")
        master.geometry("650x480")

        self.style = Style(theme='superhero')

        # Crear pestañas
        notebook = ttk.Notebook(master)
        notebook.pack(fill='both', expand=True, padx=10, pady=10)

        # Frame para compresión
        frame_compress = ttk.Frame(notebook)
        notebook.add(frame_compress, text="Comprimir")
        self.compress_app = FileCompressorApp(frame_compress)

        # Frame para descompresión
        frame_decompress = ttk.Frame(notebook)
        notebook.add(frame_decompress, text="Descomprimir")
        self.decompress_app = FileDecompressorApp(frame_decompress)

class MainApp:
    def __init__(self, master):
        self.master = master
        master.title("PackIt!")
        master.geometry("650x480")
        self.style = Style(theme='superhero')

        # Crear pestañas
        notebook = ttk.Notebook(master)
        notebook.pack(fill='both', expand=True, padx=10, pady=10)

        # Frame para compresión
        frame_compress = ttk.Frame(notebook)
        notebook.add(frame_compress, text="Comprimir")
        self.compress_app = FileCompressorApp(frame_compress)

        # Frame para descompresión
        frame_decompress = ttk.Frame(notebook)
        notebook.add(frame_decompress, text="Descomprimir")
        self.decompress_app = FileDecompressorApp(frame_decompress)

if __name__ == "__main__":
    if sys.platform == 'win32':
        # Establece el AppUserModelID antes de crear la ventana
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("PackItAppID")

    root = tk.Tk()

    # Establecer ícono en Windows (ventana + barra de tareas)
    try:
        icon_path = resource_path("packit_icon.ico")
        root.iconbitmap(icon_path)
    except Exception as e:
        print(f"[!] Error cargando icono .ico: {e}")
        try:
            img = tk.PhotoImage(file=resource_path("packit_icon.png"))
            root.iconphoto(True, img)
        except Exception as e:
            print(f"[!] Error cargando icono alternativo: {e}")

    app = MainApp(root)
    root.mainloop()
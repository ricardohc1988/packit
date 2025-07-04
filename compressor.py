"""
Módulo para compresión y encriptación de archivos con interfaz gráfica.

Proporciona una GUI con ttkbootstrap para comprimir archivos/carpetas
y opcionalmente encriptarlos usando Fernet.
"""

import os
import threading
import tkinter as tk
from tkinter import filedialog, messagebox
import ttkbootstrap as ttk
import qrcode
from ttkbootstrap.constants import BOTH, DISABLED, NORMAL, W, LEFT, RIGHT, X
from cryptography.fernet import Fernet
from PIL import ImageTk
from utils import ERROR_MESSAGES
from utils import (
    estimate_compressed_size_and_time,
    is_valid_filename,
    compress_file_with_progress,
    format_bytes,
    encrypt_file,
)


class FileCompressorApp:
    """
    Aplicación de compresión de archivos con opción de encriptación.

    Args:
        master (tk.Tk): Ventana principal de la aplicación.
    """

    def __init__(self, master):
        self.master = master
        self.style = ttk.Style(theme='superhero')
        # Variables de control
        self.process_thread = None
        self.input_file_path = tk.StringVar()
        self.output_filename = tk.StringVar()
        self.output_folder = ""
        self.cancel_flag = {"cancelled": False}
        self.encrypt_after = tk.BooleanVar(value=False)
        self.error_messages = ERROR_MESSAGES
        self._create_widgets()

    def _create_widgets(self):
        """
        Crea y organiza todos los widgets de la interfaz gráfica principal.
        """
        main_frame = ttk.Frame(self.master, padding=20)
        main_frame.pack(fill=BOTH, expand=True)

        # Sección de entrada
        ttk.Label(
            main_frame,
            text="Seleccionar archivo o carpeta a comprimir:").pack(
            anchor=W)

        input_frame = ttk.Frame(main_frame)
        input_frame.pack(fill=X, pady=(5, 10))

        ttk.Entry(
            input_frame,
            textvariable=self.input_file_path,
            width=40,
            bootstyle="info").pack(
            side=LEFT,
            fill=X,
            expand=True,
            padx=(
                0,
                5))
        ttk.Button(input_frame,
                   text="📄 Archivo",
                   command=self._select_file,
                   bootstyle="outline-warning").pack(side=LEFT,
                                                     padx=2)
        ttk.Button(input_frame,
                   text="📁 Carpeta",
                   command=self._select_folder,
                   bootstyle="outline-warning").pack(side=LEFT)

        # Info del archivo seleccionado
        self.type_icon = ttk.Label(
            main_frame, text="", font=(
                "Arial", 12, "bold"), bootstyle="secondary")
        self.type_icon.pack(anchor=W, pady=(0, 5))
        self.info_label = ttk.Label(main_frame, text="", bootstyle="primary")
        self.info_label.pack(anchor=W, pady=(0, 10))

        # Nombre del archivo de salida
        ttk.Label(
            main_frame,
            text="Nombre del archivo comprimido:").pack(
            anchor=W)
        output_name_frame = ttk.Frame(main_frame)
        output_name_frame.pack(fill=X, pady=(5, 10))

        ttk.Entry(
            output_name_frame,
            textvariable=self.output_filename,
            width=40,
            bootstyle="info").pack(
            side=LEFT,
            fill=X,
            expand=True,
            padx=(
                0,
                5))

        # Checkbox para encriptación
        ttk.Checkbutton(
            output_name_frame,
            text="Encriptar",
            variable=self.encrypt_after,
            bootstyle="danger-round-toggle"
        ).pack(side=LEFT, padx=(0, 5))

        # Carpeta de destino
        ttk.Label(
            main_frame,
            text="Carpeta destino:").pack(
            anchor=W,
            pady=(
                10,
                0))
        folder_frame = ttk.Frame(main_frame)
        folder_frame.pack(fill=X, pady=(5, 10))

        self.folder_label = ttk.Label(
            folder_frame, text="", bootstyle="primary")
        self.folder_label.pack(side=LEFT, fill=X, expand=True)
        ttk.Button(folder_frame,
                   text="Seleccionar carpeta",
                   command=self._select_output_folder,
                   bootstyle="outline-info").pack(side=RIGHT)

        # Barra de progreso
        progress_header = ttk.Frame(main_frame)
        progress_header.pack(fill=X, pady=(10, 0))
        ttk.Label(progress_header, text="Progreso:").pack(side=LEFT, anchor=W)

        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(
            main_frame,
            variable=self.progress_var,
            maximum=100,
            bootstyle="info",
            mode='determinate'
        )
        self.progress_bar.pack(fill=X, pady=(0, 5))

        # Botones de acción
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill=X)

        self.process_button = ttk.Button(
            btn_frame,
            text="Comprimir",
            command=self._start_process,
            bootstyle="outline-success"
        )
        self.process_button.pack(side=LEFT)

        self.cancel_button = ttk.Button(
            btn_frame,
            text="Cancelar",
            command=self._cancel_process,
            bootstyle="outline-danger",
            state=DISABLED
        )
        self.cancel_button.pack(side=LEFT, padx=(10, 0))

    def _select_file(self):
        """
        Abre un cuadro de diálogo para seleccionar un archivo del sistema.
        Actualiza el campo de entrada con la ruta seleccionada.
        """
        selected = filedialog.askopenfilename(
            title="Seleccionar archivo",
            filetypes=[("Todos los archivos", "*.*")]
        )
        if selected:
            self._set_input_path(selected)

    def _select_folder(self):
        """
        Abre un cuadro de diálogo para seleccionar una carpeta.
        Actualiza el campo de entrada con la ruta seleccionada.
        """
        selected = filedialog.askdirectory(title="Seleccionar carpeta")
        if selected:
            self._set_input_path(selected)

    def _select_output_folder(self):
        """
        Abre un cuadro de diálogo para seleccionar la carpeta de destino
        donde se guardará el archivo comprimido o encriptado.
        """
        folder = filedialog.askdirectory(title="Seleccionar carpeta destino")
        if folder:
            self.output_folder = folder
            self.folder_label.config(text=folder)

    def _set_input_path(self, path):
        """
        Establece la ruta del archivo o carpeta seleccionada, sugiere el
        nombre del archivo de salida y actualiza la información visual.

        Args:
            path (str): Ruta del archivo o carpeta seleccionada.
        """
        self.input_file_path.set(path)
        base_name = os.path.basename(path.rstrip("/\\"))

        if os.path.isdir(path):
            suggested = base_name + ".tar.gz"
            self.type_icon.config(
                text="📁 Carpeta seleccionada",
                bootstyle="info")
        else:
            suggested = base_name if base_name.endswith(
                ".gz") else base_name + ".gz"
            self.type_icon.config(
                text="📄 Archivo seleccionado",
                bootstyle="warning")

        self.output_filename.set(suggested)
        self.output_folder = os.path.dirname(path)
        self.folder_label.config(text=self.output_folder)
        self._update_info(path)

    def _update_info(self, path):
        """
        Muestra una estimación del tamaño y tiempo de compresión
        para el archivo o carpeta seleccionada.

        Args:
            path (str): Ruta del archivo o carpeta a analizar.
        """
        original, estimated, time_sec = estimate_compressed_size_and_time(path)
        msg = f"Tamaño original: {format_bytes(original)}   ·   "
        msg += f"Estimado comprimido: {format_bytes(estimated)}   ·   "
        msg += f"Tiempo estimado: {time_sec:.1f} s"
        self.info_label.config(text=msg)

    def _validate_inputs(self):
        """
        Valida los datos ingresados por el usuario antes de iniciar
        la compresión. Verifica que se haya seleccionado una entrada,
        se haya definido un nombre de salida válido, y que exista
        una carpeta destino.

        Returns:
            bool: True si los datos son válidos, False si falta algún dato.
        """
        input_path = self.input_file_path.get()
        output_name = self.output_filename.get().strip()

        if not input_path:
            messagebox.showwarning(
                "Datos incompletos",
                "Debe seleccionar un archivo o carpeta para comprimir")
            return False

        if not output_name:
            messagebox.showwarning(
                "Datos incompletos",
                "Debe especificar un nombre para el archivo comprimido")
            return False

        if not self.output_folder:
            messagebox.showwarning(
                "Datos incompletos",
                "Debe seleccionar una carpeta destino")
            return False

        if not is_valid_filename(output_name):
            messagebox.showwarning("Nombre inválido",
                                   "El nombre contiene caracteres no permitidos.\n"
                                   "No se permiten: < > : \" / \\ | ? *"
                                   )
            return False

        return True

    def _start_process(self):
        """
        Valida los datos y lanza el proceso de compresión (y opcionalmente
        encriptación) en un hilo separado. También maneja posibles
        confirmaciones del usuario.
        """
        if not self._validate_inputs():
            return

        input_path = self.input_file_path.get()
        output_name = self.output_filename.get().strip()

        # Asegurar extensión correcta
        if os.path.isdir(input_path) and not output_name.endswith(".tar.gz"):
            output_name += ".tar.gz"
        elif os.path.isfile(input_path) and not output_name.endswith(".gz"):
            output_name += ".gz"

        self.output_filename.set(output_name)
        final_path = os.path.join(self.output_folder, output_name)

        # Verificar sobreescritura
        if os.path.exists(final_path):
            confirm = messagebox.askyesno(
                "Confirmar", f"'{output_name}' ya existe. ¿Deseas sobrescribirlo?")
            if not confirm:
                return

        # Confirmar encriptación si está activada
        if self.encrypt_after.get():
            confirm = messagebox.askyesno(
                "Confirmar",
                "¿Estás seguro de que deseas encriptar el archivo?\n"
                "(Asegúrate de guardar la clave, sin ella no podrás recuperar los datos)"
            )
            if not confirm:
                self.encrypt_after.set(False)

        self.cancel_flag = {"cancelled": False}
        self.process_button.config(state=DISABLED)
        self.cancel_button.config(state=NORMAL)
        self.progress_var.set(0)

        self.process_thread = threading.Thread(
            target=self._run_process,
            args=(input_path, final_path),
            daemon=True
        )
        self.process_thread.start()

    def _cancel_process(self):
        """
        Activa una bandera para cancelar el proceso de compresión
        en ejecución.
        """
        self.cancel_flag["cancelled"] = True
        self.master.update()

    def _run_process(self, input_path, output_path):
        """
        Ejecuta el proceso de compresión en segundo plano.

        Args:
            input_path (str): Ruta del archivo o carpeta a comprimir.
            output_path (str): Ruta de destino del archivo comprimido.
        """
        success = compress_file_with_progress(
            input_path=input_path,
            output_path=output_path,
            progress_var=self.progress_var,
            cancel_flag=self.cancel_flag,
            progress_bar=self.progress_bar,
            progress_label=getattr(self, 'progress_label', None)
        )
        self.master.after(0, self._process_finished, success, output_path)

    def _process_finished(self, success, output_path):
        """
        Ejecuta acciones al finalizar la compresión:
        - Muestra mensajes según el resultado.
        - Si se encripta, realiza el proceso y muestra la clave generada.

        Args:
            success (bool): True si la compresión fue exitosa.
            output_path (str): Ruta del archivo comprimido.
        """
        self.process_button.config(state=NORMAL)
        self.cancel_button.config(state=DISABLED)

        if success:
            self.progress_bar.config(bootstyle="success")
            self.progress_var.set(100)

            if self.encrypt_after.get():
                # Mostrar mensaje de éxito
                messagebox.showinfo(
                    "Éxito",
                    f"Archivo comprimido correctamente en:\n{output_path}\n\n"
                    "Ahora se procederá a encriptar el archivo."
                )

                # Realizar la encriptación
                try:
                    key = Fernet.generate_key()
                    encrypted_path, used_key = encrypt_file(output_path, key)

                    # Mostrar diálogo con clave después de encriptar
                    self._show_key_dialog(used_key.decode(), encrypted_path)

                except (IOError, ValueError, PermissionError) as error:
                    self._handle_error(error, "Error al encriptar")
            else:
                # Solo compresión
                messagebox.showinfo(
                    "Éxito",
                    f"Archivo comprimido en:\n{output_path}"
                )
        else:
            self.progress_bar.config(bootstyle="danger")

        self.master.after(1000, self._reset_progress)

    def _reset_progress(self):
        """
        Restablece la barra de progreso a su valor inicial y su estilo.
        """
        self.progress_var.set(0)
        self.progress_bar.config(bootstyle="info")

    def _reset_ui(self):
        """
        Restablece los botones y el estado de la interfaz gráfica
        tras finalizar o cancelar un proceso.
        """
        self.process_button.config(state=NORMAL)
        self.cancel_button.config(state=DISABLED)
        self._reset_progress()
        self.master.update()

    def _copy_to_clipboard(self, text):
        """
        Copia un texto al portapapeles del sistema y muestra una
        confirmación visual.

        Args:
            text (str): Texto a copiar.
        """
        self.master.clipboard_clear()
        self.master.clipboard_append(text)
        self.master.update()
        messagebox.showinfo("Copiado", "Clave copiada al portapeles.")

    def _show_key_dialog(self, key_text, encrypted_path):
        """
        Muestra un cuadro de diálogo que contiene:
        - La ruta del archivo encriptado.
        - La clave generada (con opción de copiar).
        - Un código QR de la clave (y opción para guardarlo).

        Args:
            key_text (str): Clave secreta generada.
            encrypted_path (str): Ruta del archivo encriptado.
        """
        popup = tk.Toplevel(self.master)
        popup.title("Clave generada")
        popup.geometry("500x460")
        popup.resizable(False, False)
        popup.attributes('-topmost', True)
        popup.lift()

        # --- Archivo encriptado ---
        ttk.Label(
            popup,
            text="📦 Archivo encriptado:",
            bootstyle="info"
        ).pack(pady=(10, 2))
        ttk.Label(popup, text=encrypted_path, wraplength=480).pack()

        # --- Clave secreta ---
        ttk.Label(
            popup,
            text="🔑 Clave secreta (guárdala bien):",
            bootstyle="danger"
        ).pack(pady=(10, 2))

        key_entry = ttk.Entry(popup, width=60)
        key_entry.insert(0, key_text)
        key_entry.pack(pady=(0, 10))
        key_entry.config(state="readonly")

        # --- Botones arriba del QR ---
        btn_frame = ttk.Frame(popup)
        btn_frame.pack(pady=(0, 10))

        ttk.Button(
            btn_frame,
            text="📋 Copiar clave",
            command=lambda: self._copy_to_clipboard(key_text),
            bootstyle="success"
        ).pack(side=LEFT, padx=5)

        # --- QR generado dentro del mismo popup ---
        qr_code = qrcode.make(key_text)
        qr_img = qr_code.resize((220, 220))
        img_tk = ImageTk.PhotoImage(qr_img)

        qr_label = ttk.Label(popup, image=img_tk)
        qr_label.image = img_tk  # evita que se libere
        qr_label.pack(pady=5)

        ttk.Button(
            popup,
            text="💾 Guardar QR",
            command=lambda: self._save_qr_image(qr_img, popup),
            bootstyle="primary"
        ).pack(pady=(0, 10))

        ttk.Label(
            popup,
            text="⚠️ Protege esta clave. Sin ella no podrás desencriptar.",
            bootstyle="danger"
        ).pack(pady=(0, 10))

    def _save_qr_image(self, qr_img, parent=None):
        """
        Abre un diálogo para guardar el código QR generado como imagen PNG.

        Args:
            qr_img (PIL.Image): Imagen del QR a guardar.
            parent (tk.Toplevel or None): Ventana padre opcional para el diálogo.
        """
        save_path = filedialog.asksaveasfilename(
            parent=parent,
            defaultextension=".png",
            filetypes=[("PNG Image", "*.png")],
            title="Guardar QR como..."
        )
        if save_path:
            qr_img.save(save_path)
            messagebox.showinfo(
                "Guardado",
                "QR guardado correctamente.",
                parent=parent)

    def _handle_error(self, error, context=""):
        """
        Muestra un mensaje de error contextualizado y reinicia la UI.

        Args:
            error (Exception): Excepción capturada.
            context (str): Descripción opcional del contexto del error.
        """
        error_type = type(error)
        message = self.error_messages.get(error_type, str(error))

        if context:
            message = f"{context}: {message}"

        self.master.after(0, lambda: messagebox.showerror("Error", message))
        self.master.after(0, self._reset_ui)

"""
Módulo para descompresión y desencriptación de archivos con GUI.

Permite:
- Descomprimir archivos .gz o .tar.gz.
- Desencriptar archivos .enc con clave Fernet.
"""

import os
import tarfile
import tempfile
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox
from base64 import urlsafe_b64decode
import gzip
import ttkbootstrap as ttk
from cryptography.fernet import Fernet, InvalidToken
from PIL import Image
from ttkbootstrap.constants import BOTH, DISABLED, NORMAL, LEFT, RIGHT, X, W
from utils import ERROR_MESSAGES
from utils import format_bytes, decompress_file_with_progress


class FileDecompressorApp:
    """
    Aplicación GUI para descompresión y desencriptación de archivos.

    Soporta formatos .gz, .tar.gz y archivos encriptados (.enc) con Fernet.
    Proporciona una interfaz con barra de progreso y manejo de errores.
    """

    def __init__(self, master):
        self.master = master
        self.style = ttk.Style(theme='superhero')

        # Variables de control
        self.input_file_path = tk.StringVar()
        self.output_folder = ""
        self.decrypt_key = tk.StringVar()
        self.cancel_flag = {"cancelled": False}

        # Otros atributos
        self.process_thread = None
        self.error_messages = ERROR_MESSAGES

        self._create_widgets()

    def _create_widgets(self):
        """
        Crea y organiza todos los widgets de la interfaz gráfica.
        Incluye campos para seleccionar archivos, ingresar claves, mostrar progreso y botones.
        """
        main_frame = ttk.Frame(self.master, padding=20)
        main_frame.pack(fill=BOTH, expand=True)

        ttk.Label(
            main_frame,
            text="Seleccionar archivo (.enc, .gz, .tar.gz):").pack(
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
                   text="Seleccionar archivo",
                   command=self._select_file,
                   bootstyle="outline-warning").pack(side=LEFT)

        self.type_icon = ttk.Label(
            main_frame, text="", font=(
                "Arial", 12, "bold"), bootstyle="secondary")
        self.type_icon.pack(anchor=W, pady=(0, 5))
        self.info_label = ttk.Label(main_frame, text="", bootstyle="primary")
        self.info_label.pack(anchor=W, pady=(0, 10))

        ttk.Label(
            main_frame,
            text="Clave para desencriptar (si aplica):").pack(
            anchor=W)
        key_frame = ttk.Frame(main_frame)
        key_frame.pack(fill=X, pady=(5, 10))

        ttk.Entry(
            key_frame,
            textvariable=self.decrypt_key,
            width=40,
            bootstyle="info").pack(
            side=LEFT,
            fill=X,
            expand=True,
            padx=(
                0,
                5))
        ttk.Button(key_frame,
                   text="Cargar clave desde QR",
                   command=self._load_key_from_qr,
                   bootstyle="outline-info").pack(side=LEFT)

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

        progress_header = ttk.Frame(main_frame)
        progress_header.pack(fill=X, pady=(10, 0))
        ttk.Label(progress_header, text="Progreso:").pack(side=LEFT, anchor=W)

        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(
            main_frame,
            variable=self.progress_var,
            maximum=100,
            bootstyle="striped"
        )
        self.progress_bar.pack(fill=X, pady=(0, 5))

        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill=X)

        self.process_button = ttk.Button(
            btn_frame,
            text="Descomprimir",
            command=self._start_process,
            bootstyle="outline-success")
        self.process_button.pack(side=LEFT)

        self.cancel_button = ttk.Button(
            btn_frame,
            text="Cancelar",
            command=self._cancel_process,
            bootstyle="outline-danger",
            state=DISABLED)
        self.cancel_button.pack(side=LEFT, padx=(10, 0))

    def _select_file(self):
        """
        Abre un diálogo para seleccionar el archivo comprimido o encriptado.
        Actualiza el campo de entrada y muestra información del archivo.
        """
        selected = filedialog.askopenfilename(
            title="Seleccionar archivo",
            filetypes=[("Archivos encriptados y comprimidos",
                        "*.enc *.gz *.tar.gz"), ("Todos los archivos", "*.*")]
        )
        if selected:
            self.input_file_path.set(selected)
            self._update_file_info(selected)

        if not selected.endswith(".enc"):
            self.decrypt_key.set("")        

    def _select_output_folder(self):
        """
        Abre un diálogo para seleccionar la carpeta de salida.
        Actualiza la etiqueta correspondiente en la interfaz.
        """
        folder = filedialog.askdirectory(title="Seleccionar carpeta destino")
        if folder:
            self.output_folder = folder
            self.folder_label.config(text=folder)

    def _update_file_info(self, file_path):
        """
        Muestra información relevante del archivo seleccionado (nombre, tipo, tamaño).

        Args:
            file_path (str): Ruta al archivo seleccionado.
        """
        try:
            base_name = os.path.basename(file_path)
            file_size = os.path.getsize(file_path)

            if file_path.endswith(".enc"):
                file_type = "🔐 Archivo encriptado"
                color = "danger"
            elif file_path.endswith(".tar.gz"):
                file_type = "📦 Archivo TAR comprimido"
                color = "warning"
            elif file_path.endswith(".gz"):
                file_type = "🗜️ Archivo GZIP"
                color = "info"
            else:
                file_type = "📄 Archivo"
                color = "secondary"

            self.type_icon.config(
                text=f"{file_type}: {base_name}",
                bootstyle=color)

            info_text = f"Tamaño: {format_bytes(file_size)}"

            if file_path.endswith(".enc"):
                try:
                    with open(file_path, 'rb') as encrypted_file:
                        encrypted_size = len(encrypted_file.read())
                    info_text += f" | Tamaño encriptado: {format_bytes(encrypted_size)}"
                except BaseException:
                    pass

            self.info_label.config(text=info_text)

        except Exception as error:
            print(f"Error al obtener info del archivo: {error}")
            self.type_icon.config(
                text="⚠️ Archivo no accesible",
                bootstyle="danger")
            self.info_label.config(
                text="No se pudo obtener información del archivo")

    def _validate_inputs(self):
        """
        Valida los campos requeridos antes de iniciar el proceso.
        Verifica la existencia del archivo, la carpeta de salida y la clave si aplica.

        Returns:
            bool: True si todo es válido, False en caso contrario.
        """
        input_path = self.input_file_path.get()

        if not input_path:
            messagebox.showwarning(
                "Datos incompletos",
                "Debe seleccionar un archivo para procesar")
            return False

        if not self.output_folder:
            messagebox.showwarning(
                "Datos incompletos",
                "Debe seleccionar una carpeta destino")
            return False

        # Verificar si el archivo existe
        if not os.path.isfile(input_path):
            messagebox.showerror(
                "Error", "El archivo seleccionado no existe o no es válido")
            return False

        # Validación específica para archivos encriptados
        if input_path.endswith(".enc"):
            if not self.decrypt_key.get().strip():
                messagebox.showwarning(
                    "Falta clave",
                    "El archivo está encriptado, debes ingresar la clave para desencriptar.")
                return False

            # Verificar formato básico de clave Fernet
            try:
                urlsafe_b64decode(self.decrypt_key.get().encode())
                Fernet(self.decrypt_key.get().encode())
            except ValueError:
                messagebox.showerror(
                    "Clave inválida",
                    "La clave proporcionada no tiene el formato correcto")
                return False

        return True

    def _load_key_from_qr(self):
        """
        Permite cargar una clave Fernet desde un código QR contenido en una imagen.
        Utiliza pyzbar para decodificar el QR y actualiza el campo de clave.
        """
        path = filedialog.askopenfilename(
            title="Seleccionar imagen QR", filetypes=[
                ("Imagenes", "*.png *.jpg *.jpeg *.bmp")])
        if not path:
            return
        try:
            from pyzbar.pyzbar import decode
        except ImportError:
            messagebox.showerror(
                "Error", "No tienes pyzbar instalado. Instala con:\npip install pyzbar")
            return
        img = Image.open(path)
        decoded = decode(img)
        if decoded:
            key = decoded[0].data.decode()
            self.decrypt_key.set(key)
            messagebox.showinfo(
                "Clave cargada",
                "Clave cargada desde QR correctamente.")
        else:
            messagebox.showwarning(
                "No detectado",
                "No se pudo detectar un código QR válido en la imagen.")

    def _start_process(self):
        """
        Inicia el proceso de descompresión o desencriptación en un hilo separado.
        Valida entradas, desactiva botones y lanza el hilo para evitar bloquear la UI.
        """
        if not self._validate_inputs():
            return

        self.cancel_flag = {"cancelled": False}
        self.process_button.config(state=DISABLED)
        self.cancel_button.config(state=NORMAL)
        self.progress_var.set(0)

        input_path = self.input_file_path.get()
        key_text = self.decrypt_key.get().strip()
        output_folder = self.output_folder

        self.process_thread = threading.Thread(
            target=self._run_process,
            args=(input_path, key_text, output_folder),
            daemon=True
        )
        self.process_thread.start()

    def _cancel_process(self):
        """
        Señaliza que el proceso debe cancelarse y actualiza la interfaz.
        """
        self.cancel_flag["cancelled"] = True
        self.master.update()
        self.master.after(100, self._reset_ui)

    def _run_process(self, input_path, key_text, output_folder):
        """
        Ejecuta el flujo principal de procesamiento (descompresión o desencriptación).
        Detecta el tipo de archivo y llama a la función correspondiente.

        Args:
            input_path (str): Ruta al archivo de entrada.
            key_text (str): Clave de desencriptación si aplica.
            output_folder (str): Carpeta de salida.
        """
        try:
            start_time = time.time()

            if input_path.endswith(".enc"):
                files_extracted = self._process_encrypted_file(
                    input_path, key_text, output_folder, start_time
                )
            else:
                files_extracted = decompress_file_with_progress(
                    file_path=input_path,
                    output_folder=output_folder,
                    rename_on_conflict=True,
                    progress_var=self.progress_var,
                    cancel_flag=self.cancel_flag,
                    progress_bar=self.progress_bar,
                    progress_label=getattr(self, 'progress_label', None)
                )

            self.master.after(0, lambda: self._show_result(files_extracted))

        except Exception as error:
            self.master.after(
                0, lambda: self._handle_error(
                    error, "Error durante el procesamiento"))
        finally:
            self.master.after(0, self._reset_ui)

    def _process_encrypted_file(
            self, input_path, key_text, output_folder, start_time):
        """
        Desencripta y luego descomprime un archivo `.enc`.

        Args:
            input_path (str): Ruta al archivo encriptado.
            key_text (str): Clave Fernet en base64 para desencriptar.
            output_folder (str): Carpeta destino.
            start_time (float): Marca de tiempo de inicio.

        Returns:
            int: Número de archivos extraídos (0 si falla).
        """
        try:
            # 1. Desencriptar
            decrypted_data = self._decrypt_file(input_path, key_text)
            if decrypted_data is None:
                return 0

            # 2. Guardar temporal
            with tempfile.NamedTemporaryFile(delete=False, suffix=".gz") as temp_file:
                temp_path = temp_file.name
                temp_file.write(decrypted_data)

            # 3. Obtener nombre único para el archivo de salida
            original_name = os.path.basename(input_path).replace(".enc", "")

            # 4. Descomprimir
            files_extracted = decompress_file_with_progress(
                file_path=temp_path,
                output_folder=output_folder,
                rename_on_conflict=True,
                progress_var=self.progress_var,
                cancel_flag=self.cancel_flag,
                progress_bar=self.progress_bar,
                output_name=original_name,
            )
            return files_extracted

        except Exception as error:
            self._handle_error(error)
            return 0
        finally:
            if 'temp_path' in locals() and os.path.exists(temp_path):
                os.remove(temp_path)

    def _decrypt_file(self, input_path, key_text):
        """
        Desencripta un archivo `.enc` usando la clave proporcionada.

        Args:
            input_path (str): Ruta al archivo encriptado.
            key_text (str): Clave Fernet en base64.

        Returns:
            bytes or None: Datos desencriptados si fue exitoso, o None si falla.
        """
        try:
            fernet = Fernet(key_text.encode())
            with open(input_path, 'rb') as encrypted_file:
                return fernet.decrypt(encrypted_file.read())
        except InvalidToken:
            self._handle_error(InvalidToken(""))
            return None
        except Exception as error:
            self._handle_error(error, "Error al desencriptar")
            return None

    def _show_result(self, files_extracted):
        """
        Muestra al usuario el resultado del proceso según los archivos extraídos.

        Args:
            files_extracted (int): Cantidad de archivos procesados exitosamente.
        """
        if files_extracted > 0:
            self.master.after(0, lambda: messagebox.showinfo(
                "Éxito",
                f"Operación completada. {files_extracted} archivo(s) procesado(s).")
            )
        else:
            self.master.after(0, lambda: messagebox.showinfo(
                "Información",
                "No se procesaron archivos "
                "(operación cancelada o archivos existentes no sobrescritos).")
            )
        self.master.after(100, self._reset_ui)

    def _reset_ui(self):
        """
        Restaura la interfaz al estado inicial después de un proceso.
        Reactiva los botones y reinicia la barra de progreso.
        """
        self.process_button.config(state=NORMAL)
        self.cancel_button.config(state=DISABLED)
        self.progress_var.set(0)
        self.master.update()

    def _handle_error(self, error, context=""):
        """
        Muestra mensajes de error amigables al usuario según la excepción detectada.

        Args:
            error (Exception): Excepción capturada durante el proceso.
            context (str): Texto adicional para dar más contexto al error.
        """
        error_mapping = {
            InvalidToken: "La clave es incorrecta",
            gzip.BadGzipFile: "El archivo no está correctamente comprimido",
            OSError: "Error de lectura/escritura en disco",
            ValueError: "Datos corruptos o formato inválido",
            tarfile.TarError: "Error al descomprimir archivo TAR",
            Exception: f"Error inesperado: {str(error)}"
        }

        user_message = error_mapping.get(type(error), str(error))

        if context:
            user_message = f"{context}: {user_message}"

        self.master.after(0, lambda: messagebox.showerror(
            "Error",
            f"No se pudo completar la operación.\n\nDetalle: {user_message}"
        ))
        self._reset_ui()

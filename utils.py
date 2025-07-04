"""
Módulo de utilidades para compresión/descompresión y encriptación.

Contiene:
- Funciones para compresión (GZIP/TAR)
- Funciones para descompresión
- Manejo de encriptación Fernet
- Utilidades compartidas
"""

import os
import shutil
import re
import gzip
import tarfile
from base64 import urlsafe_b64encode
from hashlib import sha256
from cryptography.fernet import Fernet, InvalidToken


ERROR_MESSAGES = {
    InvalidToken: "La clave de desencriptación no es válida",
    tarfile.TarError: "Error al descomprimir archivo TAR",
    gzip.BadGzipFile: "El archivo no es un GZIP válido",
    PermissionError: "No tiene permisos para escribir en la carpeta destino",
    FileNotFoundError: "El archivo no existe o no se puede acceder",
    IsADirectoryError: "Se esperaba un archivo pero se seleccionó una carpeta",
    Exception: "Ocurrió un error inesperado al procesar el archivo"
}

def estimate_compressed_size_and_time(input_path):
    """
    Estima el tamaño comprimido y el tiempo necesario para comprimir un archivo o carpeta.

    Args:
        input_path (str): Ruta del archivo o carpeta a analizar.

    Returns:
        tuple: (tamaño original en bytes, tamaño estimado comprimido, tiempo estimado en segundos)
    """
    if not os.path.exists(input_path):
        return 0, 0, 0
    original_size = 0
    for root, _, files in os.walk(input_path) if os.path.isdir(input_path) else [(os.path.dirname(input_path), [], [os.path.basename(input_path)])]:
        for f in files:
            try:
                original_size += os.path.getsize(os.path.join(root, f))
            except:
                pass
    estimated_size = int(original_size * 0.4)
    estimated_time = original_size / (10 * 1024 * 1024)  # 10MB/s
    return original_size, estimated_size, estimated_time

def is_valid_filename(filename):
    """
    Valida si un nombre de archivo es válido para el sistema de archivos.

    Args:
        filename (str): Nombre de archivo a validar.

    Returns:
        bool: True si es válido, False si contiene caracteres no permitidos.
    """
    return not re.search(r'[<>:"/\\|?*]', filename)

def is_valid_gzip(file_path, check_contents=True):
    """
    Verifica si un archivo es un GZIP válido.

    Args:
        file_path (str): Ruta del archivo.
        check_contents (bool): Si es True, intenta leer su contenido para validar estructura interna.

    Returns:
        bool: True si es un archivo GZIP válido, False si es inválido o corrupto.
    """
    try:
        # 1. Verificar existencia y tamaño mínimo (10 bytes es el mínimo para cabecera GZIP)
        if not os.path.exists(file_path) or os.path.getsize(file_path) < 10:
            return False

        # 2. Verificar cabecera mágica (2 primeros bytes)
        with open(file_path, 'rb') as f:
            if f.read(2) != b'\x1f\x8b':
                return False

        # 3. (Opcional) Validar estructura interna
        if check_contents:
            with gzip.open(file_path, 'rb') as f:
                while f.read(1024 * 1024):  # Lee en chunks de 1MB para archivos grandes
                    pass  # Si llega aquí sin errores, el archivo es válido
        
        return True

    except (gzip.BadGzipFile, OSError, ValueError):
        return False
    except Exception as e:
        print(f"[WARNING] Error inesperado en is_valid_gzip: {str(e)}")
        return False

def get_original_gzip_name(file_path):
    """
    Intenta recuperar el nombre original del archivo desde la cabecera GZIP.

    Args:
        file_path (str): Ruta del archivo GZIP.

    Returns:
        str or None: Nombre original del archivo o None si no se pudo recuperar.
    """
    try:
        with open(file_path, 'rb') as f:
            f.seek(0)
            header = f.read(10)
            flags = header[3]
            
            if flags & 0x08:  # FLG.FNAME
                name_bytes = b""
                while True:
                    b = f.read(1)
                    if b == b'\x00' or not b:
                        break
                    name_bytes += b
                return name_bytes.decode('utf-8', errors='ignore')
    except Exception:
        return None

def compress_file_with_progress(input_path, output_path, progress_var, cancel_flag, 
                              progress_bar=None, progress_label=None, 
                              encrypt=False, password=None, overwrite_prompt=None):
    """
    Comprime un archivo o carpeta con actualización de progreso. 
    Opcionalmente también lo encripta.

    Args:
        input_path (str): Ruta del archivo o carpeta a comprimir.
        output_path (str): Ruta de salida del archivo comprimido.
        progress_var (tk.DoubleVar): Variable de progreso para la barra.
        cancel_flag (dict): Diccionario para manejar cancelación por el usuario.
        progress_bar (ttk.Progressbar, opcional): Barra de progreso a actualizar.
        progress_label (ttk.Label, opcional): Etiqueta que muestra el progreso en porcentaje.
        encrypt (bool): Si True, encripta el archivo resultante.
        password (str, opcional): Contraseña para generar la clave de encriptación.
        overwrite_prompt (callable, opcional): Función de confirmación para sobrescribir archivos existentes.

    Returns:
        bool: True si se completó correctamente, False si hubo error o cancelación.
    """
    try:
        if not os.path.exists(input_path):
            raise FileNotFoundError("El archivo de entrada no existe.")

        # Preparar nombres de archivos
        base_output = output_path
        if encrypt:
            # Si vamos a encriptar, el archivo comprimido tendrá extensión .tar.gz
            if not base_output.endswith('.tar.gz'):
                base_output = os.path.splitext(base_output)[0] + '.tar.gz'
            enc_path = os.path.splitext(base_output)[0] + '.enc'
            
            # Verificar si el archivo encriptado ya existe
            if os.path.exists(enc_path) and overwrite_prompt:
                if not overwrite_prompt(f"El archivo encriptado {os.path.basename(enc_path)} ya existe. ¿Desea sobrescribirlo?"):
                    return False

        # Verificar si el archivo comprimido ya existe
        if os.path.exists(base_output) and overwrite_prompt:
            if not overwrite_prompt(f"El archivo comprimido {os.path.basename(base_output)} ya existe. ¿Desea sobrescribirlo?"):
                return False

        if os.path.isfile(input_path):
            # Caso 1: Comprimir un archivo individual (usando gzip)
            file_size = os.path.getsize(input_path)
            with open(input_path, 'rb') as f_in, \
                 gzip.open(base_output, 'wb') as f_out:
                
                bytes_processed = 0
                chunk_size = 65536  # 64KB
                
                while True:
                    if cancel_flag["cancelled"]:
                        return False
                    
                    chunk = f_in.read(chunk_size)
                    if not chunk:
                        break
                    
                    f_out.write(chunk)
                    bytes_processed += len(chunk)
                    progress = (bytes_processed / file_size) * 100
                    update_progress(
                        progress_var=progress_var,
                        progress_bar=progress_bar,
                        progress_label=progress_label,
                        value=progress,
                        operation="Comprimiendo archivo"
                    )
        
        elif os.path.isdir(input_path):
            # Caso 2: Comprimir una carpeta (usando tar.gz)
            folder_name = os.path.basename(input_path)
            parent_dir = os.path.dirname(input_path)
            total_files = sum(len(files) for _, _, files in os.walk(input_path))
            files_processed = 0
            
            with tarfile.open(base_output, "w:gz") as tar:
                for root, _, files in os.walk(input_path):
                    for file in files:
                        if cancel_flag["cancelled"]:
                            return False
                        
                        full_path = os.path.join(root, file)
                        # Calcula la ruta relativa dentro del tar
                        rel_path = os.path.relpath(full_path, parent_dir)
                        
                        # Añade al archivo comprimido con la estructura correcta
                        tar.add(
                            full_path,
                            arcname=rel_path,  # Esto controla la estructura interna
                            recursive=False
                        )
                        
                        files_processed += 1
                        progress = (files_processed / total_files) * 100
                        update_progress(
                            progress_var=progress_var,
                            progress_bar=progress_bar,
                            progress_label=progress_label,
                            value=progress,
                            operation=f"Comprimiendo {folder_name}"
                        )

        # Encriptación si está habilitada
        if encrypt and password:           
            # Generar clave de encriptación
            key = urlsafe_b64encode(sha256(password.encode()).digest())
            fernet = Fernet(key)
            
            # Leer archivo comprimido
            with open(base_output, 'rb') as f:
                original_data = f.read()
            
            # Encriptar
            encrypted_data = fernet.encrypt(original_data)
            
            # Escribir archivo encriptado
            with open(enc_path, 'wb') as f:
                f.write(encrypted_data)
            
            # Actualizar progreso a 100% después de encriptar
            update_progress(
                progress_var=progress_var,
                progress_bar=progress_bar,
                progress_label=progress_label,
                value=100,
                operation="Encriptación completada"
            )

        return True

    except Exception as e:
        print(f"Error durante compresión/encriptación: {str(e)}")
        return False
    
    except Exception as e:
        print(f"Error durante compresión: {str(e)}")
        return False

def decompress_file_with_progress(file_path, output_folder, progress_var, cancel_flag, 
                                progress_bar=None, progress_label=None, output_name=None,
                                rename_on_conflict=False):
    """
    Descomprime un archivo .gz o .tar.gz mostrando progreso y manejando conflictos.

    Args:
        file_path (str): Ruta del archivo comprimido.
        output_folder (str): Carpeta de destino para los archivos extraídos.
        progress_var (tk.DoubleVar): Variable de progreso.
        cancel_flag (dict): Diccionario de control de cancelación.
        progress_bar (ttk.Progressbar, opcional): Barra de progreso.
        progress_label (ttk.Label, opcional): Etiqueta de porcentaje.
        output_name (str, opcional): Nombre forzado para el archivo resultante.
        rename_on_conflict (bool): Si True, renombra archivos/carpetas existentes.

    Returns:
        int: Cantidad de archivos extraídos (0 si se cancela o falla).
    """
    try:
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Archivo no encontrado: {file_path}")

        if not is_valid_gzip(file_path):
            raise ValueError("El archivo no es un GZIP válido")

        if tarfile.is_tarfile(file_path):  # Caso TAR.GZ
            with tarfile.open(file_path, "r:*") as tar_file:
                # Determinar si todos los archivos están dentro de una carpeta común
                members = [m for m in tar_file.getmembers() if m.name]
                common_prefix = os.path.commonprefix([m.name for m in members]) if members else ""
                
                if common_prefix:
                    # Obtener el nombre de la carpeta raíz
                    root_folder = common_prefix.split('/')[0]
                    original_dest = os.path.join(output_folder, root_folder)
                    dest_path = original_dest
                    
                    # Manejar conflicto de carpetas
                    if os.path.exists(dest_path):
                        if rename_on_conflict:
                            counter = 1
                            while os.path.exists(dest_path):
                                dest_path = f"{original_dest} ({counter})"
                                counter += 1
                        else:
                            # Si no queremos renombrar, extraemos igualmente (sobrescribiendo)
                            pass
                    
                    # Extraer todos los miembros manteniendo estructura
                    for member in members:
                        if cancel_flag["cancelled"]:
                            return 0
                        tar_file.extract(member, output_folder)
                    
                    # Si renombramos la carpeta, necesitamos mover los archivos
                    if dest_path != original_dest and rename_on_conflict:
                        # Primero extraemos a temporal
                        temp_dir = os.path.join(output_folder, f"temp_{root_folder}")
                        os.makedirs(temp_dir)
                        for member in members:
                            tar_file.extract(member, temp_dir)
                        
                        # Luego movemos a la ubicación final
                        shutil.move(os.path.join(temp_dir, root_folder), dest_path)
                        shutil.rmtree(temp_dir)
                    
                    # Contar archivos extraídos
                    extracted_count = sum(1 for m in members if m.isfile())
                    
                    # Actualizar progreso
                    if progress_var is not None:
                        progress_var.set(100)
                    if progress_bar:
                        progress_bar['value'] = 100
                    if progress_label:
                        progress_label.config(text="100%")
                    
                    return extracted_count
                else:
                    # Si no hay prefijo común, extraer archivos individualmente
                    file_members = [m for m in tar_file.getmembers() 
                                  if m.isfile() and not m.name.startswith(('/', '\\'))]
                    total_members = len(file_members)
                    extracted_count = 0
                    
                    for member in file_members:
                        if cancel_flag["cancelled"]:
                            return 0
                        
                        clean_name = os.path.normpath(member.name).split(os.sep)[-1]
                        dest_path = os.path.join(output_folder, clean_name)
                        
                        if os.path.exists(dest_path) and rename_on_conflict:
                            base, ext = os.path.splitext(clean_name)
                            counter = 1
                            while os.path.exists(os.path.join(output_folder, f"{base} ({counter}){ext}")):
                                counter += 1
                            dest_path = os.path.join(output_folder, f"{base} ({counter}){ext}")
                        elif os.path.exists(dest_path):
                            continue
                        
                        with tar_file.extractfile(member) as source, \
                             open(dest_path, 'wb') as target:
                            shutil.copyfileobj(source, target)
                        
                        extracted_count += 1
                        progress = (extracted_count / total_members) * 100
                        update_progress(
                            progress_var=progress_var,
                            progress_bar=progress_bar,
                            progress_label=progress_label,
                            value=progress,
                            operation="Extrayendo archivos"
                        )
                    
                    return extracted_count

        else:  # Caso GZIP normal
            original_name = get_original_gzip_name(file_path)
            final_name = original_name or output_name or "archivo_sin_nombre"
            
            final_name = os.path.basename(final_name)
            output_path = os.path.join(output_folder, final_name)

            if os.path.exists(output_path) and rename_on_conflict:
                output_path = generate_unique_filename(output_path)

            with gzip.open(file_path, 'rb') as gzip_file, \
                 open(output_path, 'wb') as f_out:
                chunk_size = 65536
                bytes_read = 0
                total_size = os.path.getsize(file_path)
                
                while True:
                    if cancel_flag["cancelled"]:
                        return 0
                    chunk = gzip_file.read(chunk_size)
                    if not chunk:
                        break
                    f_out.write(chunk)
                    bytes_read += len(chunk)
                    progress = (bytes_read / total_size) * 100
                    update_progress(
                        progress_var=progress_var,
                        progress_bar=progress_bar,
                        progress_label=progress_label,
                        value=progress,
                        operation="Descomprimiendo archivo"
                    )
            return 1

    except Exception as error:
        print(f"Error durante descompresión: {str(error)}")
        return 0
    
def generate_unique_filename(original_path):
    """
    Genera un nombre único para un archivo que ya existe añadiendo sufijos (1), (2), etc.

    Args:
        original_path (str): Ruta original del archivo.

    Returns:
        str: Nueva ruta con un nombre único que no colisiona con archivos existentes.
    """
    base, ext = os.path.splitext(original_path)
    counter = 1
    new_path = f"{base} ({counter}){ext}"
    
    while os.path.exists(new_path):
        counter += 1
        new_path = f"{base} ({counter}){ext}"
    
    return new_path
    
def encrypt_file(file_path, key=None):
    """
    Encripta un archivo usando Fernet y elimina el original.

    Args:
        file_path (str): Ruta del archivo a encriptar.
        key (bytes, opcional): Clave Fernet. Si no se proporciona, se genera una nueva.

    Returns:
        tuple: (ruta del archivo encriptado, clave usada)
    """
    key = key or Fernet.generate_key()
    fernet = Fernet(key)

    with open(file_path, 'rb') as f:
        data = f.read()
    encrypted = fernet.encrypt(data)

    encrypted_path = file_path + ".enc"
    with open(encrypted_path, 'wb') as f:
        f.write(encrypted)

    os.remove(file_path)
    return encrypted_path, key

def format_bytes(size):
    """
    Convierte una cantidad de bytes a una cadena legible (KB, MB, GB, TB).

    Args:
        size (int): Tamaño en bytes.

    Returns:
        str: Tamaño formateado.
    """
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"

def update_progress(progress_var, progress_bar, value, operation="", progress_label=None):
    """
    Actualiza visualmente la barra de progreso y su etiqueta, y cambia su estilo según el porcentaje.

    Args:
        progress_var (tk.DoubleVar): Variable de progreso.
        progress_bar (ttk.Progressbar): Barra de progreso.
        value (float): Valor del progreso entre 0 y 100.
        operation (str): Texto descriptivo de la operación (no se usa visualmente aquí).
        progress_label (ttk.Label, opcional): Etiqueta de texto que muestra el porcentaje.
    """
    try:
        progress_var.set(value)
        
        # Lógica de cambio de color
        if value < 30:
            style = "striped.danger"
        elif value < 70:
            style = "striped.warning"
        else:
            style = "striped.success"
        
        progress_bar.config(bootstyle=style)
        
        if progress_label:
            progress_label.config(text=f"{int(value)}%")

    except Exception as error:
        print(f"Error en update_progress: {error}")
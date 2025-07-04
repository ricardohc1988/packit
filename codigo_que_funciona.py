    # def _process_encrypted_file(self, input_path, key_text, output_folder, start_time):
    #     temp_path = None  # Inicializa para usarlo en finally

    #     try:
    #         # 1. Desencriptar
    #         decrypted_data = self._decrypt_file(input_path, key_text)
    #         if decrypted_data is None:
    #             print("Desencriptación fallida o cancelada.")
    #             return
            
    #         # 2. Guardar archivo temporal en carpeta temporal del sistema
    #         with tempfile.NamedTemporaryFile(delete=False, suffix=".gz") as temp_file:
    #             temp_file.write(decrypted_data)
    #             temp_path = temp_file.name
            
    #         print(f"📦 Archivo desencriptado temporal creado: {temp_path}")
            
    #         # 3. Validar si es GZIP válido
    #         if not self._is_valid_gzip(temp_path):
    #             raise ValueError("El archivo desencriptado no es un GZIP válido")

    #         # 4. Obtener nombre real esperado (ej: "documento.pdf")
    #         original_name = os.path.basename(input_path).replace(".enc", "")
            
    #         # 5. Descomprimir con nombre deseado
    #         print("🔄 Llamando a _decompress_file()...")
    #         files_extracted = self._decompress_file(temp_path, output_folder, start_time, output_name=original_name)
    #         print(f"✅ Archivos extraídos: {files_extracted}")
    #         self._show_result(files_extracted)

    #     except Exception as e:
    #         self._handle_error(e)

    #     finally:
    #         # 6. Limpieza del archivo temporal
    #         if temp_path and os.path.exists(temp_path):
    #             try:
    #                 os.remove(temp_path)
    #                 print(f"🗑️ Archivo temporal eliminado: {temp_path}")
    #             except Exception as e:
    #                 print(f"⚠️ No se pudo eliminar archivo temporal: {e}")

    # def _decrypt_file(self, input_path, key_text):
    #     """Desencripta un archivo y devuelve los datos"""
    #     try:
    #         fernet = Fernet(key_text.encode())
    #         with open(input_path, 'rb') as f_in:
    #             return fernet.decrypt(f_in.read())
    #     except InvalidToken:
    #         self._handle_error(InvalidToken(""))
    #         return None
    #     except Exception as e:
    #         self._handle_error(e, "Error al desencriptar")
    #         return None
        
    # def _decompress_file(self, file_path, output_folder, start_time, output_name=None):
    #     """Maneja .gz y .tar.gz después de desencriptar"""
    #     try:
    #         if not os.path.exists(file_path):
    #             raise FileNotFoundError(f"Archivo no encontrado: {file_path}")

    #         # ✅ Detectar si es .tar.gz
    #         if tarfile.is_tarfile(file_path):
    #             with tarfile.open(file_path, "r:*") as tar:
    #                 members = tar.getmembers()
    #                 total = len(members)

    #                 for i, member in enumerate(members):
    #                     if self.cancel_flag["cancelled"]:
    #                         return 0

    #                     tar.extract(member, path=output_folder)
    #                     progress = ((i + 1) / total) * 100
    #                     self._update_progress(progress, "Extrayendo .tar.gz")

    #                 return total  # número de archivos extraídos

    #         # Leer nombre original desde cabecera gzip (si existe)
    #         with gzip.open(file_path, 'rb') as f_in:
    #             original_name = None
    #             with open(file_path, 'rb') as raw_f:
    #                 raw_f.seek(0)
    #                 header = raw_f.read(10)
    #                 flags = header[3]

    #                 if flags & 0x08:  # FLG.FNAME
    #                     name_bytes = b""
    #                     while True:
    #                         b = raw_f.read(1)
    #                         if b == b'\x00' or not b:
    #                             break
    #                         name_bytes += b
    #                     original_name = name_bytes.decode('utf-8', errors='ignore')

    #             final_name = original_name or output_name or "archivo_sin_nombre"
    #             output_path = os.path.join(output_folder, final_name)

    #             if os.path.exists(output_path):
    #                 overwrite = messagebox.askyesno(
    #                     "Archivo existente",
    #                     f"'{final_name}' ya existe. ¿Sobrescribirlo?"
    #                 )
    #                 if not overwrite:
    #                     return 0

    #             with open(output_path, 'wb') as f_out:
    #                 chunk_size = 65536
    #                 bytes_read = 0
    #                 while True:
    #                     if self.cancel_flag["cancelled"]:
    #                         return 0
    #                     chunk = f_in.read(chunk_size)
    #                     if not chunk:
    #                         break
    #                     f_out.write(chunk)
    #                     bytes_read += len(chunk)
    #                     progress = (bytes_read / os.path.getsize(file_path)) * 100
    #                     self._update_progress(progress, "Descomprimiendo .gz")

    #             return 1  # un solo archivo descomprimido

    #     except Exception as e:
    #         self._handle_error(e, "Error al descomprimir")
    #         return 0
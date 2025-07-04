# PackIt!

**PackIt!** es una aplicación de escritorio para Windows desarrollada en Python con interfaz gráfica (GUI) usando Tkinter y TtkBootstrap. Permite comprimir y descomprimir archivos o carpetas con la opción de encriptarlos mediante una clave personalizada para mayor seguridad.

## Características

- Compresión y descompresión de archivos y carpetas.
- Opción de encriptar archivos comprimidos con una clave.
- Desencriptado automático al descomprimir, si se proporciona la clave correcta.
- Interfaz intuitiva y moderna gracias a [ttkbootstrap](https://ttkbootstrap.readthedocs.io/en/latest/).

## Requisitos

- Python 3.9 o superior
- Sistema operativo: **Windows**

## Instalación

1. Clona este repositorio:

   ```bash
   git clone https://github.com/tu-usuario/packit.git
   cd packit

2. Crea el entorno virtual con pipenv e instala dependencias::

   ```bash
   pipenv install

3. Activa el entorno virtual
   ```bash
   pipenv shell

4. Ejecuta la aplicación:
   python packit.py  

## Dependencias

- ttkbootstrap
- cryptography
- Pillow
- qrcode
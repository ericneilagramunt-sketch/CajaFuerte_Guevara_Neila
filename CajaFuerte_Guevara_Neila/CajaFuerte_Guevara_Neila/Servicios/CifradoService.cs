using System;
using System.IO;
using System.Security.Cryptography;

namespace CajaFuerte_Guevara_Neila.Servicios
{
    public class CifradoService
    {
        /*
         * FORMATO DEL ARCHIVO .caja:
         *
         * 1. Salt: 16 bytes (posiciones 0-15).
         * 2. Nonce: 12 bytes (posiciones 16-27).
         * 3. Tag: 16 bytes (posiciones 28-43).
         * 4. Texto cifrado: desde la posición 44 hasta el final.
         *
         * La clave se obtiene con PBKDF2, SHA-256 y 600.000 iteraciones.
         */

        private const int SaltSize = 16;
        private const int NonceSize = 12;
        private const int TagSize = 16;
        private const int KeySize = 32;
        private const int Iteraciones = 600000;

        // Cifra un archivo .txt y genera un archivo con extensión .caja.
        public string Cifrar(string rutaArchivo, string password)
        {
            if (!File.Exists(rutaArchivo))
                throw new FileNotFoundException("No se encuentra el archivo.");

            if (!Path.GetExtension(rutaArchivo).Equals(".txt", StringComparison.OrdinalIgnoreCase))
                throw new ArgumentException("Solo se pueden cifrar archivos .txt.");

            // Leemos el contenido original del archivo.
            byte[] datos = File.ReadAllBytes(rutaArchivo);

            // Creamos una sal, un nonce y una etiqueta de autenticación nuevos.
            byte[] salt = RandomNumberGenerator.GetBytes(SaltSize);
            byte[] nonce = RandomNumberGenerator.GetBytes(NonceSize);
            byte[] tag = new byte[TagSize];

            // Derivamos una clave AES de 256 bits a partir de la contraseña.
            byte[] clave = Rfc2898DeriveBytes.Pbkdf2(
                password,
                salt,
                Iteraciones,
                HashAlgorithmName.SHA256,
                KeySize
            );

            byte[] cifrado = new byte[datos.Length];

            try
            {
                // AES-GCM cifra los datos y genera el tag para comprobar su integridad.
                using (AesGcm aes = new AesGcm(clave, TagSize))
                {
                    aes.Encrypt(nonce, datos, cifrado, tag);
                }

                // Unimos los diferentes bloques siguiendo el formato definido.
                byte[] resultado = new byte[
                    SaltSize + NonceSize + TagSize + cifrado.Length
                ];

                Buffer.BlockCopy(salt, 0, resultado, 0, SaltSize);
                Buffer.BlockCopy(nonce, 0, resultado, SaltSize, NonceSize);
                Buffer.BlockCopy(tag, 0, resultado, SaltSize + NonceSize, TagSize);
                Buffer.BlockCopy(cifrado, 0, resultado, SaltSize + NonceSize + TagSize, cifrado.Length);

                string rutaSalida = Path.ChangeExtension(rutaArchivo, ".caja");

                // Evitamos sobrescribir un archivo cifrado que ya exista.
                if (File.Exists(rutaSalida))
                    throw new IOException("Ya existe un archivo cifrado con ese nombre.");

                File.WriteAllBytes(rutaSalida, resultado);

                return rutaSalida;
            }
            finally
            {
                // Eliminamos la clave derivada de la memoria cuando terminamos.
                CryptographicOperations.ZeroMemory(clave);
            }
        }

        // Descifra un archivo .caja si la contraseña y los datos son correctos.
        public string Descifrar(string rutaArchivo, string password)
        {
            if (!File.Exists(rutaArchivo))
                throw new FileNotFoundException("No se encuentra el archivo.");

            if (!Path.GetExtension(rutaArchivo).Equals(".caja", StringComparison.OrdinalIgnoreCase))
                throw new ArgumentException("Solo se pueden descifrar archivos .caja.");

            byte[] datos = File.ReadAllBytes(rutaArchivo);

            int cabeceraSize = SaltSize + NonceSize + TagSize;

            // Comprobamos que el archivo tenga al menos el tamaño de la cabecera.
            if (datos.Length < cabeceraSize)
                throw new InvalidDataException("El archivo no tiene un formato válido.");

            // Recuperamos la sal, el nonce y el tag guardados en el archivo.
            byte[] salt = new byte[SaltSize];
            byte[] nonce = new byte[NonceSize];
            byte[] tag = new byte[TagSize];

            Buffer.BlockCopy(datos, 0, salt, 0, SaltSize);
            Buffer.BlockCopy(datos, SaltSize, nonce, 0, NonceSize);
            Buffer.BlockCopy(datos, SaltSize + NonceSize, tag, 0, TagSize);

            // Extraemos el contenido cifrado, que empieza después de la cabecera.
            byte[] cifrado = new byte[datos.Length - cabeceraSize];

            Buffer.BlockCopy(
                datos,
                cabeceraSize,
                cifrado,
                0,
                cifrado.Length
            );

            // Volvemos a calcular exactamente la misma clave usando la contraseña introducida y la sal que venía en el archivo.
            byte[] clave = Rfc2898DeriveBytes.Pbkdf2(
                password,
                salt,
                Iteraciones,
                HashAlgorithmName.SHA256,
                KeySize
            );

            byte[] descifrado = new byte[cifrado.Length];

            try
            {
                // Intentamos descifrar.AES-GCM comprueba el tag antes de aceptar el contenido descifrado.
                using (AesGcm aes = new AesGcm(clave, TagSize))
                {
                    aes.Decrypt(nonce, cifrado, tag, descifrado);
                }

                string directorio = Path.GetDirectoryName(Path.GetFullPath(rutaArchivo))!;
                string nombre = Path.GetFileNameWithoutExtension(rutaArchivo);
                     // Preparamos el nombre para el archivo de texto recuperado.
                string rutaSalida = Path.Combine(
                    directorio,
                    nombre + "_descifrado.txt"
                );

                      // Evitamos pisar un archivo que ya estuviera creado por si acaso.
                if (File.Exists(rutaSalida))
                throw new IOException("Ya existe el archivo descifrado con ese nombre.");
                      // Escribimos el contenido limpio y recuperado en el disco.
                File.WriteAllBytes(rutaSalida, descifrado);

                return rutaSalida;
            }
            finally
            {
                // Limpiamos la clave de la memoria RAM para mantenernos seguros.
          CryptographicOperations.ZeroMemory(clave);
            }
        }
    }
}

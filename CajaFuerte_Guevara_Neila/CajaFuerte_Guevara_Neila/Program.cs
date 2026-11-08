using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using CajaFuerte_Guevara_Neila.Servicios;

// Creamos el servicio que se encarga del cifrado y descifrado.
CifradoService servicio = new CifradoService();

bool salir = false;

// Mantenemos el menú activo hasta que el usuario seleccione salir.
while (!salir)
{
    Console.WriteLine();
    Console.WriteLine("=================================");
    Console.WriteLine("          CAJAFUERTE");
    Console.WriteLine("=================================");
    Console.WriteLine("1. Cifrar archivo .txt");
    Console.WriteLine("2. Descifrar archivo .caja");
    Console.WriteLine("3. Salir");
    Console.WriteLine("=================================");
    Console.Write("Selecciona una opción: ");

    string opcion = Console.ReadLine() ?? "";

    switch (opcion)
    {
        case "1":
            Console.WriteLine();
            Console.Write("Introduce la ruta del archivo .txt: ");
            string rutaCifrar = (Console.ReadLine() ?? "").Trim().Trim('"');

            Console.Write("Introduce la contraseña: ");
            string passwordCifrar = LeerPassword();

            if (string.IsNullOrEmpty(passwordCifrar))
            {
                Console.WriteLine("La contraseña no puede estar vacía.");
                break;
            }

            try
            {
                // Llamamos al método que cifra el archivo.
                string resultado = servicio.Cifrar(rutaCifrar, passwordCifrar);

                Console.WriteLine();
                Console.WriteLine("Archivo cifrado correctamente.");
                Console.WriteLine("Archivo generado: " + resultado);
            }
            catch (Exception ex)
            {
                Console.WriteLine();
                Console.WriteLine("No se ha podido cifrar el archivo.");
                Console.WriteLine("Motivo: " + ex.Message);
            }

            break;

        case "2":
            Console.WriteLine();
            Console.Write("Introduce la ruta del archivo .caja: ");
            string rutaDescifrar = (Console.ReadLine() ?? "").Trim().Trim('"');

            Console.Write("Introduce la contraseña: ");
            string passwordDescifrar = LeerPassword();

            if (string.IsNullOrEmpty(passwordDescifrar))
            {
                Console.WriteLine("La contraseña no puede estar vacía.");
                break;
            }

            try
            {
                // Intentamos recuperar el contenido original del archivo.
                string resultado = servicio.Descifrar(
                    rutaDescifrar,
                    passwordDescifrar
                );

                Console.WriteLine();
                Console.WriteLine("Archivo descifrado correctamente.");
                Console.WriteLine("Archivo generado: " + resultado);
            }
            catch (CryptographicException)
            {
                // Este error aparece si la contraseña no es correcta o se han modificado los datos.
                Console.WriteLine();
                Console.WriteLine("ERROR: La contraseña es incorrecta o el archivo ha sido modificado.");
                Console.WriteLine("No se ha recuperado ningún contenido.");
            }
            catch (Exception ex)
            {
                Console.WriteLine();
                Console.WriteLine("No se ha podido descifrar el archivo.");
                Console.WriteLine("Motivo: " + ex.Message);
            }

            break;

        case "3":
            salir = true;
            Console.WriteLine("Cerrando CajaFuerte...");
            break;

        default:
            Console.WriteLine("Opción no válida. Inténtalo de nuevo.");
            break;
    }
}

// Lee la contraseña sin mostrar los caracteres reales por pantalla.
static string LeerPassword()
{
    StringBuilder password = new StringBuilder();

    while (true)
    {
        ConsoleKeyInfo tecla = Console.ReadKey(true);

        if (tecla.Key == ConsoleKey.Enter)
        {
            Console.WriteLine();
            return password.ToString();
        }

        // Permite borrar el último carácter introducido.
        if (tecla.Key == ConsoleKey.Backspace)
        {
            if (password.Length > 0)
            {
                password.Length--;
                Console.Write("\b \b");
            }
        }
        else if (!char.IsControl(tecla.KeyChar))
        {
            password.Append(tecla.KeyChar);
            Console.Write("*");
        }
    }
}
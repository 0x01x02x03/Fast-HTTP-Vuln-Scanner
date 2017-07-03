/*
 Base64.c:  Base64 Encoder/Decoder Implementation.
 Implementacion de Base64 *libre* de bugs

*/
#include "base64.h"

unsigned int Base64EncodeGetLength( unsigned long size )
{
/*
    Function: Base64EncodeGetLength
    Parametros: Size
    Dado un numero 'size' de bytes, devuelve la longitud de la cadena una vez que
    se convierta a base64. (4 bytes por cada 3 de entrada)
*/
    DWORD BASE64_INPUT = 3;
    DWORD BASE64_OUTPUT = 4;
    return (((size + BASE64_INPUT - 1) / BASE64_INPUT) * BASE64_OUTPUT);
}

unsigned int Base64DecodeGetLength( unsigned long size )
{
/*
    Function: Base64DecodeGetLength
    Parametros: Size
    Dado un numero 'size' de bytes, devuelve la longitud de la cadena una vez que
    se convierta de base64 a Ascii. (3 bytes por cada 4 de entrada)
    NOTA: El tamaño real puede diferir en un byte por ejemplo una cadena de 8 bytes
    pasara a tener 12 en base64 y el resultado de esta funcion seria 9. El tamaño
    real se puede obtener tras la llamada a Base64Decode.
*/
    DWORD BASE64_INPUT = 4;
    DWORD BASE64_OUTPUT = 3;
    return (((size + BASE64_INPUT - 1) / BASE64_INPUT) * BASE64_OUTPUT);
}

/******************************************************************************/
 
 
 static const char base64digits[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
 
 #define BAD     -1
 static const char base64val[] = {
     BAD,BAD,BAD,BAD, BAD,BAD,BAD,BAD, BAD,BAD,BAD,BAD, BAD,BAD,BAD,BAD,
     BAD,BAD,BAD,BAD, BAD,BAD,BAD,BAD, BAD,BAD,BAD,BAD, BAD,BAD,BAD,BAD,
     BAD,BAD,BAD,BAD, BAD,BAD,BAD,BAD, BAD,BAD,BAD, 62, BAD,BAD,BAD, 63,
      52, 53, 54, 55,  56, 57, 58, 59,  60, 61,BAD,BAD, BAD,BAD,BAD,BAD,
     BAD,  0,  1,  2,   3,  4,  5,  6,   7,  8,  9, 10,  11, 12, 13, 14,
      15, 16, 17, 18,  19, 20, 21, 22,  23, 24, 25,BAD, BAD,BAD,BAD,BAD,
     BAD, 26, 27, 28,  29, 30, 31, 32,  33, 34, 35, 36,  37, 38, 39, 40,
      41, 42, 43, 44,  45, 46, 47, 48,  49, 50, 51,BAD, BAD,BAD,BAD,BAD
 };
 #define DECODE64(c)  (isascii(c) ? base64val[c] : BAD)


// void to64frombits(unsigned char *out, const unsigned char *in, int inlen)
int Base64Encode( unsigned char* out, const unsigned char* in, int inlen )
 {
/*
    Function: Base64Encode
    Parametros: buffer de salida (out), cadena en ascii (in) y longitud de la cadena
    (intlen)
    Return: Se devolverá el numero de bytes de la nueva cadena.

    *NOTA* No se utilizara ningun '\0' para especificar el fin de la cadena por lo
    que se debera tener cuidado de no cometer desbordamientos de buffer manejando
    los datos de salida (ej: strlen(), strcpy(), ..)
*/
 int resultado=Base64EncodeGetLength(inlen);
         for (; inlen >= 3; inlen -= 3)
         {
                 *out++ = base64digits[in[0] >> 2];
                 *out++ = base64digits[((in[0] << 4) & 0x30) | (in[1] >> 4)];
                 *out++ = base64digits[((in[1] << 2) & 0x3c) | (in[2] >> 6)];
                 *out++ = base64digits[in[2] & 0x3f];
                 in += 3;
         }
 
         if (inlen > 0)
         {
                 unsigned char fragment;
 
                 *out++ = base64digits[in[0] >> 2];
                 fragment = (in[0] << 4) & 0x30;
 
                 if (inlen > 1)
                         fragment |= in[1] >> 4;
 
                 *out++ = base64digits[fragment];
                 *out++ = (inlen < 2) ? '=' : base64digits[(in[1] << 2) & 0x3c];
                 *out++ = '=';
         }
        /* *out = '\0'; //Solo en el caso de que se envie un byte mas para
        almacenar ese caracter
        */
         return(resultado);
}
/*****************************************************************************/ 
int Base64Decode( char* out, const char* in, unsigned long size )
 {
 /*
    Function: Base64Decode
    Parametros: buffer de salida (out), cadena en Base64 (in) y longitud de la
        cadena Base64 (size).
    Return: Se devolverá el numero de bytes de la nueva cadena que puede diferir
    (siendo menor) que el devuelto por Base64DecodeGetLength().

    *NOTA* No se utilizara ningun '\0' para especificar el fin de la cadena por lo
    que se debera tener cuidado de no cometer desbordamientos de buffer manejando
    los datos de salida (ej: strlen(), strcpy(), ..)

    *NOTA2* El parámetro size no es utilizado por la funcion. Ha sido añadido por
    compatibilidad con otras implementaciones de Base64
*/
         int len = 0;
         register unsigned char digit1, digit2, digit3, digit4;
 
         if (in[0] == '+' && in[1] == ' ')
                 in += 2;
         if (*in == '\r')
                 return(0);
 
         do {
                 digit1 = in[0];
                 if (DECODE64(digit1) == BAD)
                         return(-1);
                 digit2 = in[1];
                 if (DECODE64(digit2) == BAD)
                         return(-1);
                 digit3 = in[2];
                 if (digit3 != '=' && DECODE64(digit3) == BAD)
                         return(-1);
                 digit4 = in[3];
                 if (digit4 != '=' && DECODE64(digit4) == BAD)
                         return(-1);
                 in += 4;
                 *out++ = (DECODE64(digit1) << 2) | (DECODE64(digit2) >> 4);
                 ++len;
                 if (digit3 != '=')
                 {
                         *out++ = ((DECODE64(digit2) << 4) & 0xf0) | (DECODE64(digit3) >> 2);
                         ++len;
                         if (digit4 != '=')
                         {
                                 *out++ = ((DECODE64(digit3) << 6) & 0xc0) | DECODE64(digit4);
                                 ++len;
                         }
                 }
         } while (*in && *in != '\r' && digit4 != '=');
 
         return (len);
 }
/******************************************************************************/

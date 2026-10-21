using System;
using System.Linq;
using System.Text;

namespace BluntOTP
{
    public static class Base32
    {
        // Base32 alphabet
        public static char[] ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".ToCharArray();

        // Base32 padding character
        public static char PADDING = '=';

        // 5 bits per Base32 character
        public static int CHAR_SIZE_BITS = (int)Math.Log(ALPHABET.Length, 2);
        // 8 bits per byte
        public static int BYTE_SIZE_BITS = 8;
        // 40 bits per chunk
        public static int CHUNK_SIZE_BITS = LeastCommonMultiple(CHAR_SIZE_BITS, BYTE_SIZE_BITS);
        // 5 bytes per chunk
        public static int CHUNK_SIZE_BYTES = CHUNK_SIZE_BITS / BYTE_SIZE_BITS;
        // 8 characters per chunk
        public static int CHUNK_SIZE_CHARS = CHUNK_SIZE_BITS / CHAR_SIZE_BITS;

        public static string Encode(byte[] data)
        {
            StringBuilder Result = new StringBuilder();

            for (int CHUNK_INDEX = 0; CHUNK_INDEX < Math.Ceiling((double)data.Length / CHUNK_SIZE_BYTES); CHUNK_INDEX++)
            {
                long Chunk = 0;
                for (int BYTE_INDEX = 0; BYTE_INDEX < CHUNK_SIZE_BYTES; BYTE_INDEX++)
                {
                    if (data.Length > CHUNK_INDEX * CHUNK_SIZE_BYTES + BYTE_INDEX)
                        Chunk = (Chunk << BYTE_SIZE_BITS) + data[CHUNK_INDEX * CHUNK_SIZE_BYTES + BYTE_INDEX];
                    else
                        Chunk = Chunk << BYTE_SIZE_BITS;
                }

                char[] Chars = new char[CHUNK_SIZE_CHARS];
                for (int CHAR_INDEX = 0; CHAR_INDEX < CHUNK_SIZE_CHARS; CHAR_INDEX++)
                {
                    Chars[CHAR_INDEX] = ALPHABET[(int)(Chunk >> (CHAR_INDEX * CHAR_SIZE_BITS)) & (ALPHABET.Length - 1)];
                }
                if (BitConverter.IsLittleEndian)
                    Chars = Chars.Reverse().ToArray();

                string Encoded = new string(Chars);
                if (data.Length - (CHUNK_INDEX * CHAR_SIZE_BITS) < CHAR_SIZE_BITS)
                {
                    Encoded = Encoded.Substring(0, (data.Length - (CHUNK_INDEX * CHUNK_SIZE_BYTES)) * 2);
                    Encoded = Encoded.PadRight(CHUNK_SIZE_CHARS, PADDING);
                }
                Result.Append(Encoded);
            }

            return Result.ToString();
        }

        public static byte[] Decode(string data)
        {
            char[] Chars = data.TrimEnd(PADDING).ToCharArray();

            byte[] Result = new byte[(int)Math.Floor((double)Chars.Length * CHAR_SIZE_BITS / BYTE_SIZE_BITS)];

            for (int CHUNK_INDEX = 0; CHUNK_INDEX < Math.Ceiling((double)Chars.Length / CHUNK_SIZE_CHARS); CHUNK_INDEX++)
            {
                long Chunk = 0;
                for (int CHAR_INDEX = 0; CHAR_INDEX < CHUNK_SIZE_CHARS; CHAR_INDEX++)
                {
                    if (Chars.Length > CHUNK_INDEX * CHUNK_SIZE_CHARS + CHAR_INDEX)
                        Chunk = (Chunk << CHAR_SIZE_BITS) + (byte)Array.IndexOf(ALPHABET, Chars[CHUNK_INDEX * CHUNK_SIZE_CHARS + CHAR_INDEX]);
                    else
                        Chunk = (Chunk << CHAR_SIZE_BITS);
                }

                byte[] Bytes = new byte[CHUNK_SIZE_BYTES];
                for (int BYTE_INDEX = 0; BYTE_INDEX < CHUNK_SIZE_BYTES; BYTE_INDEX++)
                {
                    Bytes[BYTE_INDEX] = (byte)((Chunk >> (BYTE_INDEX * BYTE_SIZE_BITS)) & Byte.MaxValue);
                }
                if (BitConverter.IsLittleEndian)
                    Bytes = Bytes.Reverse().ToArray();

                Buffer.BlockCopy(Bytes, 0, Result, CHUNK_INDEX * CHUNK_SIZE_BYTES, Math.Min(CHUNK_SIZE_BYTES, Result.Length - (CHUNK_INDEX * CHUNK_SIZE_BYTES)));
            }

            return Result;
        }

        private static int GreatestCommonDivisor(int a, int b)
        {
            while (b != 0)
            {
                int temp = b;
                b = a % b;
                a = temp;
            }
            return Math.Abs(a);
        }

        private static int LeastCommonMultiple(int a, int b)
        {
            if (a == 0 || b == 0)
                return 0;

            return Math.Abs(a / GreatestCommonDivisor(a, b) * b);
        }
    }
}

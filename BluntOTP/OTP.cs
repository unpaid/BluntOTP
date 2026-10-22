using System;
using System.Linq;
using System.Security.Cryptography;

namespace BluntOTP
{
    public class OTP
    {
        public static string GenerateTOTP(byte[] key, int period = 30, int digits = 6, string algorithm = "SHA1")
        {
            return GenerateTOTP(key, DateTimeOffset.Now.ToUniversalTime().ToUnixTimeSeconds(), period, digits, algorithm);
        }

        public static string GenerateTOTP(byte[] key, long time, int period = 30, int digits = 6, string algorithm = "SHA1")
        {
            // T is the current Unix time in seconds.
            long T = time;

            // T0 is the epoch as specified in seconds as an offset from Unix
            // time (e.g. if using Unix time, then T0 is 0).
            int T0 = 0;

            // TX is the length of one-time duration (default is 30 seconds),
            // also known as the "time step" (or "period" in terms of the TOTP
            // URI).
            int TX = period;

            // CT is the count of the number of durations (TX) between the start
            // (T0) and now (T).
            long CT = (T - T0) / TX;

            byte[] CTbytes = new byte[8];
            BitConverter.GetBytes(CT).CopyTo(CTbytes, 0);
            if (BitConverter.IsLittleEndian)
                Array.Reverse(CTbytes);

            return GenerateOTP(key, CTbytes, digits, algorithm);
        }

        public static string GenerateHOTP(byte[] key, long counter, int digits = 6, string algorithm = "SHA1")
        {
            byte[] C = BitConverter.GetBytes(counter);
            if (BitConverter.IsLittleEndian)
                Array.Reverse(C);

            return GenerateOTP(key, C, digits, algorithm);
        }

        public static string GenerateOTP(byte[] key, byte[] data, int digits = 6, string algorithm = "SHA1")
        {
            // Calculate hash
            byte[] Hash = HMACSHA(key, data, algorithm);

            // Truncate hash to 4 bytes using the low-order half of the last
            // byte as an offset
            int Offset = Hash[Hash.Length - 1] & 0xF;
            byte[] Truncated = new byte[4];
            Buffer.BlockCopy(Hash, Offset, Truncated, 0, Truncated.Length);
            // We treat the dynamic binary code as a 31-bit, unsigned,
            // big-endian integer; the first byte is masked with a 0x7f.
            Truncated[0] = (byte)(Truncated[0] & 0x7F);

            // Convert our bytes to a string; transform to match desired digits
            if (BitConverter.IsLittleEndian)
                Array.Reverse(Truncated);
            string Result = BitConverter.ToInt32(Truncated, 0).ToString();
            if (Result.Length > digits)
                Result = Result.Substring(Result.Length - digits);
            else if (Result.Length < digits)
                Result = Result.PadLeft(digits, '0');

            return Result;
        }

        public static byte[] HMACSHA(byte[] key, byte[] data, string algorithm = "SHA1")
        {
            // The HMAC class does have a `Create` initializer that takes an
            // algorithm name, though it's deprecated and I couldn't seem to get
            // it to work.
            //HMAC hMAC = HMAC.Create(algorithm);

            switch (algorithm)
            {
                default:
                case "SHA1":
                    using (HMACSHA1 HMAC = new HMACSHA1(key))
                        return HMAC.ComputeHash(data);
                case "SHA256":
                    using (HMACSHA256 HMAC = new HMACSHA256(key))
                        return HMAC.ComputeHash(data);
                case "SHA512":
                    using (HMACSHA512 HMAC = new HMACSHA512(key))
                        return HMAC.ComputeHash(data);
            }
        }
    }
}

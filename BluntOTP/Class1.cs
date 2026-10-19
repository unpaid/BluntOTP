using System.Security.Cryptography;

namespace BluntOTP
{
    public class Class1
    {
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
                    using (HMACSHA256 HMAC = new HMACSHA256(key))
                        return HMAC.ComputeHash(data);
            }
        }
    }
}

using System.Net;
using System.Runtime.CompilerServices;
using System.Security;
using System.Text;

[assembly: InternalsVisibleTo("TacacsPlusCoreTest")]
namespace Petrsnd.TacacsPlusCore.Utils
{
    public static class StringExtensions
    {
        public static SecureString ToSecureString(this string thisString)
        {
            if (string.IsNullOrWhiteSpace(thisString))
                return null;
            var result = new SecureString();
            foreach (var c in thisString)
                result.AppendChar(c);
            return result;
        }

        public static string ToInsecureString(this SecureString thisSecureString)
        {
            return new NetworkCredential(string.Empty, thisSecureString).Password;
        }

        public static byte[] GetUserBuffer(this string user)
        {
            // I'm not sure if this is right...but probably works in most cases
            return Encoding.UTF8.GetBytes(user);
        }
    }
}

using System;

namespace ECToken.Tests.Utils
{
    public static class DateTimeExtensions
    {
        public static int FromEpoch(this DateTime expirationTime)
        {
            TimeSpan t = expirationTime - new DateTime(1970, 1, 1);
            return (int)t.TotalSeconds;
        }
    }
}

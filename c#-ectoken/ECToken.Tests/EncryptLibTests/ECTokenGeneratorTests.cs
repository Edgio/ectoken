using System;
using ecencryptstdlib;
using ECToken.Tests.Utils;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace ECToken.Tests.EncryptLibTests
{
    [TestClass]
    public class ECTokenGeneratorTests
    {
        [TestMethod]
        public void EncryptV3_WithDateTimeAndClientIP_ReturnsEcnryptedTokenWithBoth()
        {
            //arrange
            var generator = new ECTokenGenerator();
            var expireTime = DateTime.Now.AddMilliseconds(300);
            string clientIp = Faker.Internet.IPv4Address();
            string key = Faker.Name.FullName();

            //act
            var token = generator.EncryptV3(key, expireTime, clientIp);

            //assert

            Assert.IsNotNull(token);
            var decryptdToken = generator.DecryptV3(key, token, false);

            string expected = $"ec_expire={expireTime.FromEpoch()}&ec_clientip={clientIp}";
            Assert.AreEqual(expected, decryptdToken);
        }

        [TestMethod]
        public void EncryptV3_WithDateTimeOnly_ReturnsEncryptedTokenWithOnlyDate()
        {
            //arrange
            var generator = new ECTokenGenerator();
            var expireTime = DateTime.Now.AddMilliseconds(300);
            string key = Faker.Name.FullName();

            //act
            var token = generator.EncryptV3(key, expireTime);

            //assert
            Assert.IsNotNull(token);
            var decryptdToken = generator.DecryptV3(key, token, false);

            string expected = $"ec_expire={expireTime.FromEpoch()}";
            Assert.AreEqual(expected, decryptdToken);
        }

    }
}

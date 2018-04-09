using System;
using ecencryptstdlib;
using ECToken.Tests.Utils;
using Xunit;

namespace ECToken.Tests.EncryptLibTests
{
    
    public class ECTokenGeneratorTests
    {
        [Fact]
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

            Assert.NotNull(token);
            var decryptdToken = generator.DecryptV3(key, token, false);

            string expected = $"ec_expire={expireTime.FromEpoch()}&ec_clientip={clientIp}";
            Assert.Equal(expected, decryptdToken);
        }

        [Fact]
        public void EncryptV3_WithDateTimeOnly_ReturnsEncryptedTokenWithOnlyDate()
        {
            //arrange
            var generator = new ECTokenGenerator();
            var expireTime = DateTime.Now.AddMilliseconds(300);
            string key = Faker.Name.FullName();

            //act
            var token = generator.EncryptV3(key, expireTime);

            //assert
            Assert.NotNull(token);
            var decryptdToken = generator.DecryptV3(key, token, false);

            string expected = $"ec_expire={expireTime.FromEpoch()}";
            Assert.Equal(expected, decryptdToken);
        }

        [Fact]
        public void NextRandomString_WithLength_ReturnsStringWithSpecifiedSize()
        {
            //arrange
            var generator = new ECTokenGenerator();
            int length = 50;

            //act
            var random = generator.NextRandomString(50);

            //assert
            Assert.Equal(length, random.Length);
        }

        [Fact]
        public void NextRandomString_WithNoLength_ReturnsStringBetweenMINAndMAX()
        {
            //arrange
            var generator = new ECTokenGenerator();
            int lengthMin = 4;
            int lengthMax = 8;
            //act
            var random = generator.NextRandomString();

            //assert
            Assert.True(random.Length >= lengthMin && random.Length <= lengthMax);
        }


        [Fact]
        public void NextRandomString_ReturnsString()
        {
            //arrange
            var generator = new ECTokenGenerator();

            //act
            var random = generator.NextRandomString();

            //assert
            Assert.IsType<string>(random);
        }

    }
}

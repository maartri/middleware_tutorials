using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;

using middleware_tutorials.Policies;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using Microsoft.Extensions.Options;
using Microsoft.AspNetCore.Authorization;

using middleware_tutorials.Models;
using System.Security.Claims;
using System.Security.Principal;
using System.IdentityModel.Tokens.Jwt;

// For more information on enabling Web API for empty projects, visit http://go.microsoft.com/fwlink/?LinkID=397860

namespace middleware_tutorials.Controllers
{
    [Route("api/[controller]")]
    public class LoginController : Controller
    {
        private readonly IssuerOptions _jwtOptions;
        private readonly ILogger _logger;
        private readonly JsonSerializerSettings _serializeSettings;

        public LoginController(IOptions<IssuerOptions> jwtOptions, ILoggerFactory loggerFactory) {
            _jwtOptions = jwtOptions.Value;
            ThrowIfInvalidOptions(_jwtOptions);

            _logger = loggerFactory.CreateLogger<LoginController>();
            _serializeSettings = new JsonSerializerSettings
            {
                Formatting = Formatting.Indented
            };
        }

        [AllowAnonymous, HttpPost]
        public async Task<IActionResult> Get([FromForm] ApplicationUser user) {
            var identity = await GetClaimsIdentity(user);

            if (identity == null) {
                _logger.LogInformation("Invalid credentials");
                return BadRequest("Invalid Credentials");
            }

            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.GivenName, user.UserName),
                new Claim(JwtRegisteredClaimNames.Jti, await _jwtOptions.JtiGenerator()),
                new Claim(JwtRegisteredClaimNames.Iat, ToUnixEpochDate(_jwtOptions.IssuedAt).ToString(), ClaimValueTypes.Integer64),
                identity.FindFirst("DisneyCharacter")
            };

            var jwt = new JwtSecurityToken(
                   issuer: _jwtOptions.Issuer,
                   audience: _jwtOptions.Audience,
                   claims: claims,
                   notBefore: _jwtOptions.NotBefore,
                   expires: _jwtOptions.Expiration,
                   signingCredentials: _jwtOptions.SigningCredentials
                );

            var encodedjwt = new JwtSecurityTokenHandler().WriteToken(jwt);
            var response = new
            {
                access_token = encodedjwt,
                expires_in = (int)_jwtOptions.ValidFor.TotalSeconds
            };

            var json = JsonConvert.SerializeObject(response, _serializeSettings);
            return new OkObjectResult(json);
        }

        private static void ThrowIfInvalidOptions(IssuerOptions options)
        {
            if (options == null) throw new ArgumentNullException(nameof(options));

            if (options.ValidFor <= TimeSpan.Zero)
            {
                throw new ArgumentException("Must be a non-zero TimeSpan.", nameof(IssuerOptions.ValidFor));
            }

            if (options.SigningCredentials == null)
            {
                throw new ArgumentNullException(nameof(IssuerOptions.SigningCredentials));
            }

            if (options.JtiGenerator == null)
            {
                throw new ArgumentNullException(nameof(IssuerOptions.JtiGenerator));
            }
        }

        private static Task<ClaimsIdentity> GetClaimsIdentity(ApplicationUser user)
        {
            if (user.UserName == "MickeyMouse" &&
                user.Password == "MickeyMouseIsBoss123")
            {
                return Task.FromResult(new ClaimsIdentity(new GenericIdentity(user.UserName, "Token"),
                  new[]
                  {
                    new Claim("DisneyCharacter", "IAmMickey")
                  }));
            }

            if (user.UserName == "NotMickeyMouse" &&
                user.Password == "NotMickeyMouseIsBoss123")
            {
                return Task.FromResult(new ClaimsIdentity(new GenericIdentity(user.UserName, "Token"),
                  new Claim[] { }));
            }

            // Credentials are invalid, or account doesn't exist
            return Task.FromResult<ClaimsIdentity>(null);
        }

        /// <returns>Date converted to seconds since Unix epoch (Jan 1, 1970, midnight UTC).</returns>
        private static long ToUnixEpochDate(DateTime date)
          => (long)Math.Round((date.ToUniversalTime() - new DateTimeOffset(1970, 1, 1, 0, 0, 0, TimeSpan.Zero)).TotalSeconds);


    }
}

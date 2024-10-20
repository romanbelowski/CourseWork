using Microsoft.AspNetCore.Mvc;
using System.Net.Http;
using System.Text.Json;

namespace CourseWork.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class CaptchaController : ControllerBase
    {
        private readonly IConfiguration _configuration;
        private readonly HttpClient _httpClient;

        public CaptchaController(IConfiguration configuration, HttpClient httpClient)
        {
            _configuration = configuration;
            _httpClient = httpClient;
        }

        [HttpPost("Verify")]
        public async Task<IActionResult> VerifyreCaptcha([FromBody] string userResponse)
        {
            var reCaptchaSecretKey = _configuration["RecaptchaSettings:SecretKey"];
            if (string.IsNullOrEmpty(reCaptchaSecretKey) || string.IsNullOrEmpty(userResponse))
            {
                return BadRequest("Invalid reCAPTCHA configuration or user response");
            }

            var content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                {"secret", reCaptchaSecretKey },
                {"response", userResponse }
            });

            var response = await _httpClient.PostAsync("https://www.google.com/recaptcha/api/siteverify", content);
            if (response.IsSuccessStatusCode)
            {
                var responseString = await response.Content.ReadAsStringAsync();
                var result = JsonSerializer.Deserialize<reCaptchaResponse>(responseString);
                return Ok(result.Success);
            }

            return BadRequest("Failed to verify reCAPTCHA");
        }

        private class reCaptchaResponse
        {
            public bool Success { get; set; }
            public string[] ErrorCodes { get; set; }
        }
    }
}
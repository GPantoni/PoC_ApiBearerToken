using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.BearerToken;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace PoC_ApiBearerToken.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    [HttpGet("/login")]
    public IActionResult Login(string username, string password)
    {
        if (!IsValidUser(username, password)) return Unauthorized("Invalid credentials");
        
        var claimsPrincipal = new ClaimsPrincipal(new ClaimsIdentity(new[] { new Claim(ClaimTypes.Name, username) },
            BearerTokenDefaults.AuthenticationScheme));
        
        return SignIn(claimsPrincipal);
    }

    private static bool IsValidUser(string username, string password)
    {
        return username == "glauco" && password == "123456";
    }

    [HttpGet("/user")]
    [Authorize]
    public IActionResult GetUser()
    {
        var user = User;
        if (user?.Identity?.IsAuthenticated ?? false)
        {
            return Ok($"Welcome {user.Identity.Name}");
        }

        return Unauthorized();
    }
}
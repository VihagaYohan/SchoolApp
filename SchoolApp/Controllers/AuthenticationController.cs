using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using SchoolApp.Data;
using SchoolApp.Data.Models;
using SchoolApp.Data.ViewModels;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace SchoolApp.Controllers
{
	[Route("api/[controller]")]
	[ApiController]
	public class AuthenticationController : ControllerBase
	{
		private readonly UserManager<ApplicationUser> _userManager;
		private readonly RoleManager<IdentityRole> _roleManager;
		private readonly AppDbContext _context;
		private readonly IConfiguration _configuration;
		private readonly TokenValidationParameters _tokenValidationParameters;

		public AuthenticationController(UserManager<ApplicationUser> userManager,
			RoleManager<IdentityRole> roleManager,
			AppDbContext context,
			IConfiguration configutation,
			TokenValidationParameters tokenValidationParameters)
		{
			this._userManager = userManager;
			this._roleManager = roleManager;
			this._context = context;
			this._configuration = configutation;
			this._tokenValidationParameters = tokenValidationParameters;
		}

		[HttpPost("register-user")]
		public async Task<IActionResult> Register([FromBody]RegisterVM model) 
		{
			if (!ModelState.IsValid) 
			{
				return BadRequest("Please provide all required fields");
			}
			var userExists = await _userManager.FindByEmailAsync(model.EmailAddress);
			if (userExists != null) 
			{
				return BadRequest($"User {model.EmailAddress} already exists");
			}

			ApplicationUser newUser = new ApplicationUser()
			{
				FirstName = model.FirstName,
				LastName = model.LastName,
				Email = model.EmailAddress,
				UserName = model.UserName,
				SecurityStamp  = Guid.NewGuid().ToString()
			};
			var result = await _userManager.CreateAsync(newUser, model.Password);
			if (result.Succeeded)
			{
				return Ok("User created");
			}
			else 
			{
				return BadRequest("User could not be created");
			}
		}

		[HttpPost("login-user")]
		public async Task<IActionResult> Login([FromBody] LoginVM model) 
		{
			if (!ModelState.IsValid) 
			{
				return BadRequest("Please provide all required fields");
			}
			var userExists = await _userManager.FindByEmailAsync(model.EmailAddress);
			if (userExists != null && await _userManager.CheckPasswordAsync(userExists,model.Password))
			{
				var tokenValue = await GenerateTokenAsync(userExists);

				return Ok(tokenValue);
			}
			return Unauthorized();
		}

		private async Task<AuthResultVM> GenerateTokenAsync(ApplicationUser user)
		{
			var authClaims = new List<Claim>() 
			{
				new Claim(ClaimTypes.Name,user.UserName),
				new Claim(ClaimTypes.NameIdentifier,user.Id),
				new Claim(JwtRegisteredClaimNames.Email,user.Email),
				new Claim(JwtRegisteredClaimNames.Sub,user.Email),
				new Claim(JwtRegisteredClaimNames.Jti,Guid.NewGuid().ToString())
			};

			var authSignInKey = new Microsoft.IdentityModel.Tokens.SymmetricSecurityKey(Encoding.ASCII.GetBytes(_configuration["JWT:Secret"]));

			// defining actual token
			var token = new JwtSecurityToken(
				issuer: _configuration["JWT:Issuer"],
				audience: _configuration["JWT:Audience"],
				expires: DateTime.UtcNow.AddMinutes(1),
				claims:authClaims,
				signingCredentials:new SigningCredentials(authSignInKey,SecurityAlgorithms.HmacSha256));

			// generate JWT token
			var jwtToken = new JwtSecurityTokenHandler().WriteToken(token);

			// generate refresh token
			var refreshToken = new RefreshToken()
			{
				JwtId = token.Id,
				IsRevoked = false,
				UserId = user.Id,
				DateAdded = DateTime.UtcNow,
				DateExpire = DateTime.UtcNow.AddMonths(6),
				Token = Guid.NewGuid().ToString() + "-" + Guid.NewGuid().ToString()
			};

			// save refresh token in database
			await _context.RefreshTokens.AddAsync(refreshToken);
			await _context.SaveChangesAsync();

			var response = new AuthResultVM()
			{
				Token = jwtToken,
				RefreshToken = refreshToken.Token,
				ExpireAt = token.ValidTo
			};

			return response;

		}
	}
}

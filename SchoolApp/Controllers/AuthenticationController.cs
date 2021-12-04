﻿using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using SchoolApp.Data;
using SchoolApp.Data.Models;
using SchoolApp.Data.ViewModels;
using System;
using System.Collections.Generic;
using System.Linq;
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

		public AuthenticationController(UserManager<ApplicationUser> userManager,
			RoleManager<IdentityRole> roleManager,
			AppDbContext context,
			IConfiguration configutation)
		{
			this._userManager = userManager;
			this._roleManager = roleManager;
			this._context = context;
			this._configuration = configutation;
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
				return Ok("User signed in");
			}
			return Unauthorized();
		}
	}
}

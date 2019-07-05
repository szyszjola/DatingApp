using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using DatingApp.API.Data;
using DatingApp.API.DTOs;
using DatingApp.API.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace DatingApp.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IAuthRepository _repo;
        private readonly IConfiguration _config;

        public AuthController(IAuthRepository repo, IConfiguration config)
        {
            _repo = repo;
            _config = config;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register(UserForRegisterDTO dtos)
        {
            //if not using [Api Controller]   - Register(([FromBody] UserForRegisterDTO dtos)
            //validation 
            //if(!ModelState.IsValid)
            //    return BadRequest(ModelState);

            dtos.Username = dtos.Username.ToLower();

            if (await _repo.UserExists(dtos.Username))
                return BadRequest("Username already exist");

            User userToCreate = new User
            {
                Username = dtos.Username
            };

            User createdUser = await _repo.Register(userToCreate, dtos.Password);
            return StatusCode(201);
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login(UserForLoginDTO dtos)
        {
            throw new Exception("Coputer says no!");

            var userFromRepo = await _repo.Login(dtos.Username.ToLower(), dtos.Password);
            if (userFromRepo == null)
                return Unauthorized();

            Claim[] claim = new[]
            {
                new Claim(ClaimTypes.NameIdentifier, userFromRepo.Id.ToString()),
                new Claim(ClaimTypes.Name, userFromRepo.Username)
                    };
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config.GetSection("AppSettings:Token").Value));

            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);

            var tokenDescription = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claim),
                Expires = DateTime.Now.AddDays(1),
                SigningCredentials = creds
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            var token = tokenHandler.CreateToken(tokenDescription);

            return Ok(new
            {
                token = tokenHandler.WriteToken(token)
            });
        }
    }
}
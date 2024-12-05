using AngularAuthAPI.Context;
using AngularAuthAPI.Helpers;
using AngularAuthAPI.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Text;
using System.Text.RegularExpressions;

namespace AngularAuthAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly AppDbContext _authContext;

        public UserController(AppDbContext authContext)
        {
            _authContext = authContext;
        }

        [HttpPost("authenticate")]
        public async Task<IActionResult> Authenticate([FromBody] User userObj)
        {
            if (userObj == null)
                return BadRequest();

            var user = await _authContext.Users
                            .FirstOrDefaultAsync(x => x.Username == userObj.Username);

            if(user == null)
                return NotFound(new { Message = "User Not Found!" });

            if (!PasswordHasher.VerifyPassword(userObj.Password,user.Password))
            {
                return BadRequest(new { Message = "Password is Incorrect!" });
            }

            return Ok(new
            {
                Message = "Login Success!"
            });
        }

        [HttpPost("register")]
        public async Task<IActionResult> RegisterUser([FromBody] User userObj)
        {
            if (userObj == null)
                return BadRequest();

            if (await CheckUserNameExist(userObj.Username))
                return BadRequest("Username already exist!");

            if (await CheckEmailExist(userObj.Email))
                return BadRequest("Email already exist!");

            var pass = CheckPasswordStrength(userObj.Password);
            if(!string.IsNullOrEmpty(pass))
                return BadRequest(new { Message = pass.ToString() });

            userObj.Password = PasswordHasher.HashPassword(userObj.Password);
            userObj.Role = "User";
            userObj.Token = "";

            await _authContext.Users.AddAsync(userObj);
            await _authContext.SaveChangesAsync();

            return Ok(new
            {
                Message = "User Registered!"
            });
        }

        private Task<bool> CheckUserNameExist(string username)
        => _authContext.Users.AnyAsync(x => x.Username == username);

        private Task<bool> CheckEmailExist(string email)
        => _authContext.Users.AnyAsync(x => x.Email == email);

        private string CheckPasswordStrength(string password)
        {
            StringBuilder stringBuilder = new StringBuilder();
            if(password.Length < 8)
                stringBuilder.Append("Minimum password length should be 8" + Environment.NewLine);

            if(!(Regex.IsMatch(password, "[a-z]") && Regex.IsMatch(password,"A-Z") && Regex.IsMatch(password,"0-9")))
                stringBuilder.Append("Password should be Alfanumeric" + Environment.NewLine);

            if (!Regex.IsMatch(password, "[<,>,@,!,#,$,%,&,^]"))
                stringBuilder.Append("Password should be Alfanumeric" + Environment.NewLine);

            return stringBuilder.ToString();
        }
    }
}

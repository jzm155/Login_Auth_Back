﻿namespace AngularAuthAPI.Models.Dto
{
    public record ResetPasswordDto
    {
        public string Email { get; set; }
        public string EmailToken { get; set; }
        public string NewPassword { get; set; }
        public string Password { get; set; }
    }
}

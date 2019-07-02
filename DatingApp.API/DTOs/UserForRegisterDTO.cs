﻿using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace DatingApp.API.DTOs
{
    public class UserForRegisterDTO
    {
        [Required]
        public string Username { get; set; }
        [Required]
        [StringLength(10, MinimumLength =5, ErrorMessage ="You must specify password between 5 and 10 characters")]
        public string Password { get; set; }
    }
}
